defmodule Mix.Tasks.GenerateLicenseKey do
  @shortdoc "Generates an Ed25519 keypair for Cloudflare Worker signing and Elixir verification"

  @moduledoc """
  Generates an Ed25519 public/private keypair using Erlang's `:crypto` module
  and outputs:

  1. **Elixir Public Key (Base64):** Ready to embed in `AshPhoenixStarter.Licensing.Verifier`
     or set via `LICENSE_PUBLIC_KEY`.

  ## Usage

      mix gen_license_key
  """

  use Mix.Task

  @impl Mix.Task
  def run(args) do
    # Generate raw 32-byte public key and 32-byte private seed
    {public_key, private_seed} = :crypto.generate_key(:eddsa, :ed25519)

    public_key_b64 = Base.encode64(public_key)
    public_key_b64url = Base.url_encode64(public_key, padding: false)
    private_seed_b64url = Base.url_encode64(private_seed, padding: false)

    Mix.shell().info([:green, "\n=== 1. ELIXIR PUBLIC KEY (Embed in Verifier or LICENSE_PUBLIC_KEY) ===\n"])
    Mix.shell().info(public_key_b64)
  end
end

