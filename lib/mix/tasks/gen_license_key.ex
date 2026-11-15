defmodule Mix.Tasks.GenLicenseKey do
  @shortdoc "Generates an Ed25519 keypair or signs a license using PRIV_LIC_KEY_JSON"

  @moduledoc """
  Generates an Ed25519 public/private JWK keypair or signs a license token using
  an existing JWK stored in `PRIV_LIC_KEY_JSON` (or configured `:priv_license_key_env_var`).

  ## Usage

      # Generate a brand new JWK keypair + sample signed license
      mix gen_license_key --sign --issue acme.com --tier pro --days 365

      # Sign a new license using an existing JWK stored in the environment
      PRIV_LIC_KEY_JSON='{"kty":"OKP",...}' mix gen_license_key --sign --issue client.io --tier enterprise --days 90
  """

  use Mix.Task

  @switches [
    sign: :boolean,
    issue: :string,
    tier: :string,
    days: :integer
  ]

  @impl Mix.Task
  def run(args) do
    Mix.Task.run("app.config")
    {opts, _positional, _invalid} = OptionParser.parse(args, strict: @switches)

    {public_key, private_seed, jwk_json} = load_or_generate_keypair()

    public_key_b64 = Base.encode64(public_key)

    Mix.shell().info([
      :green,
      "\n=== 1. ELIXIR PUBLIC KEY (Set in config or BASE64_ED25519_PUB_KEY) ===\n"
    ])

    Mix.shell().info(public_key_b64)

    Mix.shell().info([:cyan, "\n=== 2. JWK PRIVATE KEY JSON (Store in #{priv_env_var()}) ===\n"])
    Mix.shell().info(jwk_json)

    if opts[:sign] do
      print_signed_license(private_seed, public_key, opts)
    end
  end

  defp priv_env_var do
    Application.get_env(:encrypt_beam, :priv_license_key_env_var, "PRIV_LIC_KEY_JSON")
  end

  defp load_or_generate_keypair do
    case System.get_env(priv_env_var()) do
      json when is_binary(json) and json != "" ->
        parse_jwk!(json)

      _ ->
        {public_key, private_seed} = :crypto.generate_key(:eddsa, :ed25519)

        jwk_json =
          Jason.encode!(%{
            kty: "OKP",
            crv: "Ed25519",
            x: Base.url_encode64(public_key, padding: false),
            d: Base.url_encode64(private_seed, padding: false),
            ext: true
          })

        {public_key, private_seed, jwk_json}
    end
  end

  defp parse_jwk!(json) do
    with {:ok, %{"kty" => "OKP", "crv" => "Ed25519", "x" => x_b64, "d" => d_b64}} <-
           Jason.decode(json),
         {:ok, public_key} when byte_size(public_key) == 32 <-
           Base.url_decode64(x_b64, padding: false),
         {:ok, private_seed} when byte_size(private_seed) == 32 <-
           Base.url_decode64(d_b64, padding: false) do
      Mix.shell().info([:yellow, "\n[Loaded existing Ed25519 JWK from #{priv_env_var()}]"])
      {public_key, private_seed, String.trim(json)}
    else
      _ ->
        Mix.raise("Invalid Ed25519 JWK JSON in #{priv_env_var()}.")
    end
  end

  defp print_signed_license(private_seed, public_key, opts) do
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

    true = :crypto.verify(:eddsa, :none, payload_b64, signature, [public_key, :ed25519])

    Mix.shell().info([:green, "\n=== 3. SIGNED LICENSE KEY (#{String.upcase(tier)}) ===\n"])
    Mix.shell().info(license_key)
    Mix.shell().info("")
  end
end
