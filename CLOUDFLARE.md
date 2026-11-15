Here is the complete implementation for both the Cloudflare Worker License Server (worker.js) and the Elixir Self-Hosted LicenseClient (lib/my_app/license_client.ex).

Together, they handle first-install 7-day trials tied to an instance_id, one-click license activation, silent daily rolling renewals, and hot reloading of .beam.enc modules via EncryptBeam.check_now().


1. Cloudflare Worker License Server (worker.js)

This Worker uses WebCrypto (crypto.subtle) directly on the JWK JSON produced by mix gen_license_key (PRIV_LIC_KEY_JSON) with zero external npm dependencies. It produces tokens in the exact base64url(payload).base64url(signature) format expected by EncryptBeam.Verifier.

Prerequisites in Cloudflare

Create a KV namespace for licenses and trials and upload

```bash
npx wrangler kv namespace create LICENSES_KV
npx wrangler secret put PRIV_LIC_KEY_JSON
```

store an activation record in LICENSES_KV when a customer buys (e.g., via your Stripe webhook): ( cloudflare_worker.js is included in repo)
   • Key: code:CUST-9941-ABCD
   • Value: {"email":"buyer@acme.com","tier":"pro","active":true,"max_instances":2,"instances":[]}


Elixir Self-Hosted LicenseClient (lib/my_app/license_client.ex)

Add this module to your host application (and add MyApp.LicenseClient to :keep_unencrypted_modules in config/config.exs so it can always communicate with your Cloudflare Worker even if protected modules are unloaded).

What It Does

1. Persistent Disk Storage (/data/license_state.json): Stores a unique instance_id (generated once on first install), the user's activation_code (once activated), and the latest signed license_key.
2. Pre-Boot Hydration (load_persisted_license!/0): Called in config/runtime.exs before EncryptBeam starts so reboots immediately load the persisted token into LICENSE_KEY.
3. First-Install Trial Request: If no LICENSE_KEY exists on first boot, it automatically calls POST /api/v1/trial to fetch the 7-day starter key.
4. Hot Activation (activate/1): Called from your Phoenix LiveView/Controller when the user submits their activation code. Saves the new token, sets LICENSE_KEY, and calls EncryptBeam.check_now() to unlock protected modules immediately without a restart.
5. Daily Rolling Refresh: Silently calls POST /api/v1/activate every 24 hours to extend the rolling lease as long as their subscription remains active.

```elixir
defmodule MyApp.LicenseClient do
  @moduledoc """
  Manages self-hosted instance identity, first-install 7-day trial requests,
  one-click activation, and daily rolling license refreshes against Cloudflare.
  """
  use GenServer
  require Logger

  @refresh_interval_ms :timer.hours(24)

  # --- Pre-Boot Helper (Call from config/runtime.exs) ---

  @doc """
  Loads any persisted `license_key` from disk into `System.put_env/2` before
  `EncryptBeam` starts in the supervision tree.
  """
  def load_persisted_license! do
    state_file = state_file_path()

    with true <- File.exists?(state_file),
         {:ok, raw} <- File.read(state_file),
         {:ok, %{"license_key" => token}} when is_binary(token) and token != "" <- Jason.decode(raw) do
      token_var = Application.get_env(:encrypt_beam, :license_token_env_var, "LICENSE_KEY")
      System.put_env(token_var, token)
      :ok
    else
      _ -> :ok
    end
  end

  # --- Public API ---

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Activates a purchased license code from the frontend UI and immediately
  unlocks protected BEAM modules without restarting the server.
  """
  @spec activate(String.t()) :: {:ok, map()} | {:error, term()}
  def activate(activation_code) when is_binary(activation_code) do
    GenServer.call(__MODULE__, {:activate, String.trim(activation_code)}, 15_000)
  end

  @doc """
  Returns the unique ID for this self-hosted installation (useful to display in UI support info).
  """
  @spec instance_id() :: String.t()
  def instance_id do
    GenServer.call(__MODULE__, :instance_id)
  end

  # --- GenServer Callbacks ---

  @impl GenServer
  def init(_opts) do
    persisted = read_or_init_state_file()

    # If no valid license is currently active (e.g. brand-new install), request 7-day trial
    if not EncryptBeam.valid?() and is_nil(persisted["activation_code"]) do
      send(self(), :request_initial_trial)
    end

    schedule_daily_refresh()
    {:ok, persisted}
  end

  @impl GenServer
  def handle_call(:instance_id, _from, state) do
    {:reply, state["instance_id"], state}
  end

  @impl GenServer
  def handle_call({:activate, code}, _from, state) do
    case call_cloudflare("/api/v1/activate", %{
           activation_code: code,
           instance_id: state["instance_id"]
         }) do
      {:ok, %{"license_key" => new_token}} ->
        new_state =
          state
          |> Map.put("activation_code", code)
          |> Map.put("license_key", new_token)

        persist_and_apply!(new_state)
        status = EncryptBeam.check_now()
        {:reply, {:ok, status}, new_state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl GenServer
  def handle_info(:request_initial_trial, state) do
    case call_cloudflare("/api/v1/trial", %{instance_id: state["instance_id"]}) do
      {:ok, %{"license_key" => trial_token}} ->
        Logger.info("[LicenseClient] Activated 7-day self-hosted trial.")
        new_state = Map.put(state, "license_key", trial_token)
        persist_and_apply!(new_state)
        EncryptBeam.check_now()
        {:noreply, new_state}

      {:error, reason} ->
        Logger.warning("[LicenseClient] Could not fetch initial trial token: #{inspect(reason)}")
        {:noreply, state}
    end
  end

  @impl GenServer
  def handle_info(:daily_refresh, state) do
    new_state =
      case state["activation_code"] do
        code when is_binary(code) and code != "" ->
          case call_cloudflare("/api/v1/activate", %{
                 activation_code: code,
                 instance_id: state["instance_id"]
               }) do
            {:ok, %{"license_key" => refreshed_token}} ->
              Logger.info("[LicenseClient] Rolling license lease refreshed successfully.")
              updated = Map.put(state, "license_key", refreshed_token)
              persist_and_apply!(updated)
              EncryptBeam.check_now()
              updated

            {:error, reason} ->
              Logger.warning("[LicenseClient] License refresh failed: #{inspect(reason)}")
              state
          end

        _ ->
          state
      end

    schedule_daily_refresh()
    {:noreply, new_state}
  end

  # --- Helpers ---

  defp persist_and_apply!(state) do
    path = state_file_path()
    File.mkdir_p!(Path.dirname(path))
    File.write!(path, Jason.encode!(state, pretty: true))

    token_var = Application.get_env(:encrypt_beam, :license_token_env_var, "LICENSE_KEY")
    System.put_env(token_var, state["license_key"])
  end

  defp read_or_init_state_file do
    path = state_file_path()

    with true <- File.exists?(path),
         {:ok, raw} <- File.read(path),
         {:ok, %{"instance_id" => id} = decoded} when is_binary(id) ->
      decoded
    else
      _ ->
        initial = %{
          "instance_id" => generate_instance_id(),
          "activation_code" => nil,
          "license_key" => System.get_env("LICENSE_KEY")
        }

        File.mkdir_p!(Path.dirname(path))
        File.write!(path, Jason.encode!(initial, pretty: true))
        initial
    end
  end

  defp generate_instance_id do
    :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)
  end

  defp state_file_path do
    Application.get_env(:my_app, :license_state_path, "/data/license_state.json")
  end

  defp license_server_url do
    Application.get_env(:my_app, :license_server_url, "https://yourdomain.com")
  end

  defp call_cloudflare(path, payload) do
    url = license_server_url() <> path

    # Uses Req (or swap with :httpc / Finch / HTTPoison)
    case Req.post(url, json: payload, receive_timeout: 10_000) do
      {:ok, %{status: 200, body: body}} when is_map(body) ->
        {:ok, body}

      {:ok, %{status: status, body: body}} ->
        {:error, {status, body}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp schedule_daily_refresh do
    Process.send_after(self(), :daily_refresh, @refresh_interval_ms)
  end
end

```

1. config/runtime.exs: Hydrate LICENSE_KEY from the persisted Docker volume (/data/license_state.json) before your supervision tree boots:
```elixir
import Config

MyApp.LicenseClient.load_persisted_license!()
```
2. config/prod.exs: Keep MyApp.LicenseClient unencrypted alongside your boot and UI modules:elixir
```elixir
   config :encrypt_beam,
   app_name: :my_app,
   license_public_key: "YOUR_BASE64_ED25519_PUB_KEY",
   strict_mode: false,
   notifier: MyApp.LicenseNotifier,
   keep_unencrypted_modules: [
   MyApp.Application,
   MyApp.LicenseNotifier,
   MyApp.LicenseClient,
   MyAppWeb.Endpoint,
   MyAppWeb.Router,
   MyAppWeb.LicenseLive
   ]
```   
3. lib/my_app/application.ex: Start EncryptBeam first, followed by MyApp.LicenseClient
```elixir
   children = [
   {EncryptBeam, scan_interval_ms: :timer.minutes(5), notifier: MyApp.LicenseNotifier, strict_mode: false},
   MyApp.LicenseClient,
   {Phoenix.PubSub, name: MyApp.PubSub},
   MyApp.Repo,
   MyAppWeb.Endpoint
   ]
```   
4. LiveView Activation Handler: When a user pastes their license code into your UI form
```elixir
   def handle_event("activate_license", %{"code" => code}, socket) do
   case MyApp.LicenseClient.activate(code) do
   {:ok, status} ->
   {:noreply, socket |> assign(license: status) |> put_flash(:info, "License activated!")}

   {:error, {_status, %{"message" => msg}}} ->
   {:noreply, put_flash(socket, :error, msg)}

   {:error, _} ->
   {:noreply, put_flash(socket, :error, "Invalid or expired activation key.")}
   end
   end
```