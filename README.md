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

defmodule MyApp.Application do
  use Application

  @impl true
  def start(_type, _args) do
    children = [
      # 1. Must be FIRST: verifies license & loads encrypted .beam files into VM memory
      # Optional: pass recheck_interval_ms to enforce expiration while running
      {EncryptBeam, recheck_interval_ms: :timer.hours(1)},

      # 2. Downstream children can now safely reference encrypted modules
      MyApp.Repo,
      MyAppWeb.Endpoint
    ]

    opts = [strategy: :one_for_one, name: MyApp.Supervisor]
    Supervisor.start_link(children, opts)
  end
end

## config.ex
config :encrypt_beam,
       app_name: :my_app,
         # Public key embedded in config or provided via BASE64_ED25519_PUB_KEY
       license_public_key: System.get_env("BASE64_ED25519_PUB_KEY"),
         # Env var holding the private JWK JSON (used only when signing licenses)
       priv_license_key_env_var: "PRIV_LIC_KEY_JSON",
         # Env var holding the signed license token at runtime
       license_token_env_var: "LICENSE_KEY",
         # Env var holding the >=32-byte AES-256-GCM build/runtime secret
       encryption_secret_env_var: "APP_ENCRYPTION_SECRET",
         # Keep Application boot module and any pre-boot modules unencrypted
       keep_unencrypted_modules: [MyApp.Application],
         # Fail boot in production if license is invalid; set false in dev/test
       strict_mode: config_env() == :prod
```


## Encrypt Beams
#### 1. Generate the secret: mix gen_license_key --sign --issue acme.com --tier pro --days 365
#### 2. APP_ENCRYPTION_SECRET="your-secure-build-secret" mix encrypt_beams


Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at <https://hexdocs.pm/encrypt_beam>.

