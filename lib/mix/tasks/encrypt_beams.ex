defmodule Mix.Tasks.EncryptBeams do
  @shortdoc "Encrypts compiled BEAM binaries with AES-256-GCM"

  @moduledoc """
  Encrypts compiled `.beam` files using AES-256-GCM and outputs them to
  `priv/encrypted_beams/`.

  Automatically skips your Application boot module (and any modules listed in
  `:keep_unencrypted_modules`) so the Erlang VM can start and run `LicenseBootHook`.

  ## Usage

      APP_ENCRYPTION_SECRET="your-32-byte-or-longer-build-secret" mix encrypt_beams
      APP_ENCRYPTION_SECRET="your-32-byte-or-longer-build-secret" mix encrypt_beams --strip
  """

  use Mix.Task

  @switches [strip: :boolean]

  @impl Mix.Task
  def run(args) do
    {opts, _positional, _invalid} = OptionParser.parse(args, strict: @switches)

    Mix.Task.run("compile")

    secret_var =
      Application.get_env(:encrypt_beam, :encryption_secret_env_var, "APP_ENCRYPTION_SECRET")

    secret = System.get_env(secret_var)

    if is_nil(secret) or byte_size(secret) < 32 do
      Mix.raise(
        "ERROR: #{secret_var} environment variable must be set and at least 32 bytes long."
      )
    end

    encryption_key = :crypto.hash(:sha256, secret)
    build_dir = Mix.Project.compile_path()
    output_dir = Path.join(Mix.Project.app_path(), "priv/encrypted_beams")
    File.mkdir_p!(output_dir)

    protected_beams = EncryptBeam.BeamFilter.encryptable_beams(build_dir)

    Mix.shell().info([:green, "=== Encrypting #{length(protected_beams)} BEAM binaries ==="])

    Enum.each(protected_beams, fn beam_path ->
      filename = Path.basename(beam_path)
      plain_binary = File.read!(beam_path)

      {ciphertext, iv, tag} = encrypt_payload(plain_binary, encryption_key)
      secured_blob = <<iv::binary-size(12), tag::binary-size(16), ciphertext::binary>>

      dest_path = Path.join(output_dir, "#{filename}.enc")
      File.write!(dest_path, secured_blob)
      Mix.shell().info("Encrypted: #{filename} -> #{Path.basename(dest_path)}")
    end)

    Mix.shell().info([:green, "Successfully encrypted BEAM binaries into #{output_dir}"])

    if opts[:strip] do
      Mix.Task.run("strip_beams")
    end
  end

  defp encrypt_payload(plaintext, key) do
    iv = :crypto.strong_rand_bytes(12)
    {ciphertext, tag} = :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, plaintext, iv, true)
    {ciphertext, iv, tag}
  end
end
