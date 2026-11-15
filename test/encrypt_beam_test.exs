defmodule EncryptBeamTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  alias EncryptBeam.{LicenseWatchdog, Verifier}

  @encryption_secret "super-secret-32-byte-test-encryption-key-12345"

  defmodule TestNotifier do
    @behaviour EncryptBeam.LicenseWatchdog

    @impl true
    def on_license_status_change(status) do
      if pid =
           Process.get(:test_notify_pid) || Application.get_env(:encrypt_beam, :test_notify_pid) do
        send(pid, {:license_status_changed, status})
      end
    end
  end

  setup do
    # Generate a fresh Ed25519 keypair for each test
    {public_key, private_seed} = :crypto.generate_key(:eddsa, :ed25519)
    public_key_b64 = Base.encode64(public_key)

    jwk_json =
      Jason.encode!(%{
        kty: "OKP",
        crv: "Ed25519",
        x: Base.url_encode64(public_key, padding: false),
        d: Base.url_encode64(private_seed, padding: false),
        ext: true
      })

    # Configure application env for isolated testing
    Application.put_env(:encrypt_beam, :app_name, :encrypt_beam)
    Application.put_env(:encrypt_beam, :license_public_key, public_key_b64)
    Application.put_env(:encrypt_beam, :priv_license_key_env_var, "PRIV_LIC_KEY_JSON")
    Application.put_env(:encrypt_beam, :license_token_env_var, "LICENSE_KEY")
    Application.put_env(:encrypt_beam, :encryption_secret_env_var, "APP_ENCRYPTION_SECRET")
    Application.put_env(:encrypt_beam, :test_notify_pid, self())

    System.put_env("APP_ENCRYPTION_SECRET", @encryption_secret)
    System.put_env("PRIV_LIC_KEY_JSON", jwk_json)

    encrypted_dir = Application.app_dir(:encrypt_beam, "priv/encrypted_beams")
    File.mkdir_p!(encrypted_dir)

    on_exit(fn ->
      # Stop watchdog if still running
      if pid = Process.whereis(LicenseWatchdog) do
        GenServer.stop(pid, :normal)
      end

      # Clean up dynamically loaded test module and temporary encrypted files
      :code.purge(EncryptBeam.DynamicSecretModule)
      :code.delete(EncryptBeam.DynamicSecretModule)
      File.rm_rf!(encrypted_dir)

      System.delete_env("LICENSE_KEY")
      System.delete_env("APP_ENCRYPTION_SECRET")
      System.delete_env("PRIV_LIC_KEY_JSON")
      Application.delete_env(:encrypt_beam, :test_notify_pid)
    end)

    %{
      public_key: public_key,
      private_seed: private_seed,
      public_key_b64: public_key_b64,
      jwk_json: jwk_json,
      encrypted_dir: encrypted_dir
    }
  end

  defp sign_token(private_seed, claims) do
    payload_b64 = claims |> Jason.encode!() |> Base.url_encode64(padding: false)
    signature = :crypto.sign(:eddsa, :none, payload_b64, [private_seed, :ed25519])
    sig_b64 = Base.url_encode64(signature, padding: false)
    "#{payload_b64}.#{sig_b64}"
  end

  defp build_encrypted_test_beam!(encrypted_dir) do
    # Compile a real module in memory to get authentic BEAM bytecode
    code = """
    defmodule EncryptBeam.DynamicSecretModule do
      def secret_greeting, do: "unlocked_from_encrypted_beam"
    end
    """

    [{mod, beam_binary}] = Code.compile_string(code)

    # Purge it from the VM immediately so we prove EncryptBeam loads it from .beam.enc
    :code.purge(mod)
    :code.delete(mod)
    refute Code.ensure_loaded?(mod)

    # Encrypt using AES-256-GCM matching Mix.Tasks.EncryptBeams
    key = :crypto.hash(:sha256, @encryption_secret)
    iv = :crypto.strong_rand_bytes(12)
    {ciphertext, tag} = :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, beam_binary, iv, true)
    secured_blob = <<iv::binary-size(12), tag::binary-size(16), ciphertext::binary>>

    dest_path = Path.join(encrypted_dir, "#{mod}.beam.enc")
    File.write!(dest_path, secured_blob)
    mod
  end

  describe "Verifier.verify/2" do
    test "verifies a valid signed license token", %{private_seed: seed} do
      exp = System.system_time(:second) + 3600
      token = sign_token(seed, %{issue: "acme.com", tier: "pro", exp: exp})

      assert {:ok, %{issue: "acme.com", tier: "pro", exp: ^exp}} = Verifier.verify(token)
    end

    test "rejects an expired license token", %{private_seed: seed} do
      exp = System.system_time(:second) - 60
      token = sign_token(seed, %{issue: "acme.com", tier: "pro", exp: exp})

      assert {:error, :license_expired} = Verifier.verify(token)
    end

    test "rejects a tampered payload", %{private_seed: seed} do
      exp = System.system_time(:second) + 3600
      token = sign_token(seed, %{issue: "acme.com", tier: "pro", exp: exp})
      [_payload, sig] = String.split(token, ".")

      tampered_payload =
        %{issue: "acme.com", tier: "enterprise", exp: exp}
        |> Jason.encode!()
        |> Base.url_encode64(padding: false)

      assert {:error, :invalid_signature} = Verifier.verify("#{tampered_payload}.#{sig}")
    end
  end

  describe "Mix.Tasks.GenLicenseKey" do
    test "signs a license using PRIV_LIC_KEY_JSON from the environment" do
      output =
        capture_io(fn ->
          Mix.Tasks.GenLicenseKey.run([
            "--sign",
            "--issue",
            "env-client.io",
            "--tier",
            "enterprise",
            "--days",
            "30"
          ])
        end)

      assert output =~ "Loaded existing Ed25519 JWK from PRIV_LIC_KEY_JSON"
      assert output =~ "SIGNED LICENSE KEY (ENTERPRISE)"

      # Extract the generated token from the last non-empty line
      token =
        output
        |> String.split("\n", trim: true)
        |> List.last()
        |> String.trim()

      assert {:ok, %{issue: "env-client.io", tier: "enterprise"}} = Verifier.verify(token)
    end
  end

  describe "LicenseWatchdog supervision child & runtime unloading" do
    test "loads protected BEAMs on startup, then unloads and alerts when license expires", %{
      private_seed: seed,
      encrypted_dir: encrypted_dir
    } do
      mod = build_encrypted_test_beam!(encrypted_dir)

      # 1. Start with a valid license
      valid_token =
        sign_token(seed, %{
          issue: "acme.com",
          tier: "pro",
          exp: System.system_time(:second) + 3600
        })

      System.put_env("LICENSE_KEY", valid_token)

      {:ok, _pid} =
        start_supervised(
          {EncryptBeam, scan_interval_ms: 60_000, notifier: TestNotifier, strict_mode: false}
        )

      # Verify module was decrypted and loaded into the VM
      assert EncryptBeam.valid?() == true
      assert EncryptBeam.claims().issue == "acme.com"
      assert Code.ensure_loaded?(mod)
      assert mod.secret_greeting() == "unlocked_from_encrypted_beam"

      assert_receive {:license_status_changed, %{valid?: true, claims: %{tier: "pro"}}}

      # 2. Simulate license expiration / revocation at runtime
      expired_token =
        sign_token(seed, %{issue: "acme.com", tier: "pro", exp: System.system_time(:second) - 10})

      System.put_env("LICENSE_KEY", expired_token)

      stderr_output =
        capture_io(:stderr, fn ->
          status = EncryptBeam.check_now()
          assert status.valid? == false
          assert status.reason == :license_expired
        end)

      # Verify console alert was printed
      assert stderr_output =~ "LICENSE INVALID OR EXPIRED"

      # Verify frontend flag & notifier updated
      assert EncryptBeam.valid?() == false
      assert_receive {:license_status_changed, %{valid?: false, reason: :license_expired}}

      # Verify the protected BEAM module was purged and unloaded from the VM
      refute Code.ensure_loaded?(mod)
    end

    test "raises on boot in strict_mode when license is missing or invalid" do
      System.delete_env("LICENSE_KEY")

      capture_io(:stderr, fn ->
        assert {:error, {%RuntimeError{message: msg}, _stack}} =
                 EncryptBeam.start_link(strict_mode: true, scan_interval_ms: 60_000)

        assert msg =~ "Startup license verification failed"
      end)
    end
  end
end
