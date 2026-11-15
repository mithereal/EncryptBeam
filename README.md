# EncryptBeam

**Protect Elixir/Erlang `.beam` binaries with AES-256-GCM encryption, Ed25519-signed license keys, continuous runtime monitoring, and automatic VM module unloading.**

## Overview
`EncryptBeam` runs as a supervision tree child inside your host Elixir application. On startup, it validates an Ed25519-signed license token, decrypts protected `.beam.enc` binaries in memory, and loads them into the Erlang VM via `:code.load_binary/3` without writing plaintext bytecode to disk. It automatically purges modules if a license expires, exposes runtime flags and notifier callbacks for frontends, and supports build-time encryption via `mix encrypt_beams --strip` and JWK environment variable signing.

## Key Features & Quick Reference

- **Supervision Tree Integration:** Place `{EncryptBeam, ...}` as the first child in `MyApp.Application` so encrypted modules load before downstream workers boot.
- **Continuous License Watchdog:** Re-verifies license validity on a configurable scan interval (`scan_interval_ms`).
- **Automatic VM Unloading:** Purges and deletes invalid modules from memory immediately and invokes your optional notifier module.
- **Frontend Status Helpers:** Query `EncryptBeam.valid?()`, `EncryptBeam.status()`, or trigger `EncryptBeam.check_now()`.
- **Build & Release Workflow:** Generate keys via `mix gen_license_key --sign`, encrypt and strip binaries with `mix encrypt_beams --strip`, and pass runtime secrets via environment variables (`APP_ENCRYPTION_SECRET`, `BASE64_ED25519_PUB_KEY`, `LICENSE_KEY`).


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
  @moduledoc """
  Example host application integrating EncryptBeam as the first child
  in its supervision tree, along with a frontend notifier for LiveView/PubSub.
  """
  use Application

  @impl true
  def start(_type, _args) do
    children = [
      # 1. MUST BE FIRST: Verifies license on boot, decrypts .beam.enc files into VM memory,
      # and continuously scans for expiration/revocation.
      {EncryptBeam,
       scan_interval_ms: :timer.seconds(30),
       notifier: MyApp.LicenseNotifier,
       strict_mode: Application.get_env(:encrypt_beam, :strict_mode, true)},

      # 2. PubSub for pushing real-time license alerts to Phoenix LiveView
      {Phoenix.PubSub, name: MyApp.PubSub},

      # 3. Your database, workers, and web endpoint (safe to use protected modules now)
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
       license_public_key: System.get_env("BASE64_ED25519_PUB_KEY"),
       priv_license_key_env_var: "PRIV_LIC_KEY_JSON",
       license_token_env_var: "LICENSE_KEY",
       encryption_secret_env_var: "APP_ENCRYPTION_SECRET",
         # Continuous scan interval (e.g., every 15 seconds)
       scan_interval_ms: :timer.seconds(15),
         # Callback module that broadcasts status updates to your frontend
       notifier: MyApp.LicenseNotifier,
         # Keep False if you want the web frontend to stay online and show a license warning
       strict_mode: false,
         # Keep boot & frontend shell modules unencrypted so the UI can render when beams unload
       keep_unencrypted_modules: [
         MyApp.Application,
         MyApp.LicenseNotifier,
         MyAppWeb.Endpoint,
         MyAppWeb.Router,
         MyAppWeb.LicenseLive
       ]

```


## Encrypt Beams
#### 1. Generate the secret: mix gen_license_key --sign --issue acme.com --tier pro --days 365
#### 2. APP_ENCRYPTION_SECRET="your-secure-build-secret" mix encrypt_beams
#### 3. mix strip_beams


Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at <https://hexdocs.pm/encrypt_beam>.

