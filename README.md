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
       strict_mode: Application.get_env(:encrypt_beam, :strict_mode, true)}, # (Note: Setting strict_mode: false allows the web UI to stay online when a license expires so your frontend can display the "License Expired" banner instead of crashing the entire server.)

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
```

```elixir
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

### Hitting the Flag & Pushing to Your Frontend
 You have two ways to consume the license status in your host application's frontend:
 * Option A
 
    Frontend Notifier Module (lib/my_app/license_notifier.ex)
 
    Remember to add both MyApp.Application and MyApp.LicenseNotifier 
    (plus your Endpoint / Router / alert views) to :keep_unencrypted_modules so they stay loaded if protected domain modules are purged.

```elixir
defmodule MyApp.LicenseNotifier do
  @moduledoc """
  Receives license status updates from EncryptBeam.LicenseWatchdog and
  broadcasts them to connected frontend clients.
  """
  @behaviour EncryptBeam.LicenseWatchdog

  @impl true
  def on_license_status_change(status) do
    Phoenix.PubSub.broadcast(MyApp.PubSub, "system:license", {:license_status, status})
  end
end
```
#### In your Phoenix LiveView, subscribe to "system:license" and render the banner:
```elixir
def mount(_params, _session, socket) do
  if connected?(socket) do
    Phoenix.PubSub.subscribe(MyApp.PubSub, "system:license")
  end

  {:ok, assign(socket, license: EncryptBeam.status())}
end

def handle_info({:license_status, status}, socket) do
  {:noreply, assign(socket, license: status)}
end
```

 * Option B: Direct Polling / Plug / Controller Check
   
    Because EncryptBeam.valid?/0 and EncryptBeam.status/0 read from :persistent_term, calling them in a Phoenix Plug, GraphQL resolver, or REST endpoint takes nanoseconds and has zero GenServer bottleneck:

```elixir
defmodule MyAppWeb.LicensePlug do
  import Plug.Conn

  def init(opts), do: opts

  def call(conn, _opts) do
    status = EncryptBeam.status()

    if status.valid? do
      assign(conn, :license_status, status)
    else
      conn
      |> put_status(:payment_required)
      |> Phoenix.Controller.json(%{
        error: "license_invalid",
        reason: status.reason,
        message: status.message
      })
      |> halt()
    end
  end
end
```


## Encrypt Beams
#### 1. Generate the secret: mix gen_license_key --sign --issue acme.com --tier pro --days 365
#### 2. APP_ENCRYPTION_SECRET="your-secure-build-secret" mix encrypt_beams
#### 3. mix strip_beams


## How This Behaves at Runtime

1. Valid License: LicenseWatchdog decrypts all protected modules into memory, sets EncryptBeam.valid?() to true, and notifies MyApp.LicenseNotifier.
2. License Expires or Is Revoked: On the next scan (or via EncryptBeam.check_now()), LicenseWatchdog purges and deletes all protected .beam modules from VM memory, prints the red console alert to :stderr, flips EncryptBeam.valid?() to false, and triggers MyApp.LicenseNotifier.on_license_status_change/1 so your frontend immediately displays the alert.
3. License Renewed: Once LICENSE_KEY is updated with a valid token (or on the next scan), LicenseWatchdog automatically decrypts and reloads the modules into memory and clears the frontend warning without requiring a full server restart.

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at <https://hexdocs.pm/encrypt_beam>.

