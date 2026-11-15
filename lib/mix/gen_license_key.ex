defmodule Mix.Tasks.GenerateLicenseKey do
  @shortdoc "Generates an Ed25519 keypair Beam verification"

  @moduledoc """
  Generates an Ed25519 public/private keypair using Erlang's `:crypto` module
  and outputs:

  1. **Elixir Public Key (Base64):**
  2. **Json Private Key (JWK & PKCS#8 Base64):**
  3. **Optional Sample License Key:** Pass `--sign` to generate a ready-to-test signed
     license token immediately.

  ## Usage

      mix gen_license_key
      mix gen_license_key --sign --issue acme.com --tier pro --days 365
  """

  use Mix.Task

  @switches [
    sign: :boolean,
    issue: :issue,
    tier: :string,
    days: :integer
  ]

  @impl Mix.Task
  def run(args) do
    {opts, _positional, _invalid} = OptionParser.parse(args, strict: @switches)

    # Generate raw 32-byte public key and 32-byte private seed
    {public_key, private_seed} = :crypto.generate_key(:eddsa, :ed25519)

    public_key_b64 = Base.encode64(public_key)
    public_key_b64url = Base.url_encode64(public_key, padding: false)
    private_seed_b64url = Base.url_encode64(private_seed, padding: false)

    # WebCrypto JWK format (works natively in Cloudflare Workers without ASN.1 parsing)
    jwk_json =
      Jason.encode!(%{
        kty: "OKP",
        crv: "Ed25519",
        x: public_key_b64url,
        d: private_seed_b64url,
        ext: true
      })

    Mix.shell().info([:green, "\n=== 1. ELIXIR PUBLIC KEY (Embed in Verifier or LICENSE_PUBLIC_KEY) ===\n"])
    Mix.shell().info(public_key_b64)

    Mix.shell().info([:cyan, "\n=== 2. Json PRIVATE KEY  ===\n"])
    Mix.shell().info(jwk_json)

    if opts[:sign] do
      print_sample_license(private_seed, public_key, opts)
    end
  end

  defp print_sample_license(private_seed, public_key, opts) do
    issue = opts[:issue] || "default"
    tier = opts[:tier] || "pro"
    days = opts[:days] || 365
    exp = System.system_time(:second) + days * 86_400

    claims = %{
      issue: issue,
      tier: tier,
      exp: exp
    }

    payload_b64 = claims |> Jason.encode!() |> Base.url_encode64(padding: false)
    signature = :crypto.sign(:eddsa, :none, payload_b64, [private_seed, :ed25519])
    sig_b64 = Base.url_encode64(signature, padding: false)
    license_key = "#{payload_b64}.#{sig_b64}"

    # Sanity-check verification right away
    true = :crypto.verify(:eddsa, :none, payload_b64, signature, [public_key, :ed25519])

    Mix.shell().info([:green, "=== 3. SAMPLE SIGNED LICENSE KEY (#{String.upcase(tier)}) ===\n"])
    Mix.shell().info(license_key)
    Mix.shell().info("")
  end
end

