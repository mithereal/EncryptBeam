# EncryptBeam

**Encrypt Beam**
    Encrypt and decrypt beams using Ed25519-signed keys


## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `encrypt_beam` to your list of dependencies in `mix.exs`:


```elixir
def deps do
  [
    {:encrypt_beam, "~> 0.1.0"}
  ]
end

defmodule Myapp.Application do
  use Application

  def start(_type, _args) do
    # 1. Validate license & decrypt/load secure BEAM binaries into memory
    EncryptBeam.LicenseBootHook.verify_and_boot!()

    children = [
      # ... your normal supervision tree (Telemetry, Repos, Endpoints, etc.)
    ]

    Supervisor.start_link(children, strategy: :one_for_one)
  end
end

## config.ex
config :encrypt_beam,
  app_name: :my_app,
  priv_license_key_env_var: "PRIV_LIC_KEY_JSON",
  encryption_salt_env_var: "ENC_SALT"
```


## Encrypt Beams
#### 1. Generate the secret: mix gen_license_key --sign --issue acme.com --tier pro --days 365
#### 2. APP_ENCRYPTION_SECRET="your-secure-build-secret" mix encrypt_beams


Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at <https://hexdocs.pm/encrypt_beam>.

