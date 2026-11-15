defmodule EncryptBeam do
  @moduledoc """
  Supervision tree child that verifies Ed25519-signed license keys and
  decrypts AES-256-GCM protected BEAM binaries into memory on startup.

  Add `EncryptBeam` as the **first** child in your host application's
  supervision tree so all protected modules are loaded before other workers start.
  """
  use GenServer
  require Logger

  alias EncryptBeam.{LicenseBootHook, ProtectedLoader, Verifier}

  @type option ::
          {:recheck_interval_ms, pos_integer() | nil}
          | {:strict_mode, boolean()}
          | {:public_key, String.t()}

  @doc """
  Starts the `EncryptBeam` supervisor child and synchronously verifies the
  license and loads encrypted BEAM binaries during `init/1`.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Returns the verified license claims (`%{issue: ..., tier: ..., exp: ...}`)
  or `nil` if running in non-strict mode without a valid license.
  """
  @spec claims() :: map() | nil
  def claims do
    GenServer.call(__MODULE__, :claims)
  end

  @doc """
  Returns `true` if a valid, unexpired license was verified.
  """
  @spec valid?() :: boolean()
  def valid? do
    GenServer.call(__MODULE__, :valid?)
  end

  # --- GenServer Callbacks ---

  @impl GenServer
  def init(opts) do
    case LicenseBootHook.verify_and_boot!(opts) do
      {:ok, claims} ->
        schedule_recheck(opts)
        {:ok, %{claims: claims, valid?: true, opts: opts}}

      :ok ->
        # Non-strict mode fallback when license check fails in dev/test
        {:ok, %{claims: nil, valid?: false, opts: opts}}
    end
  end

  @impl GenServer
  def handle_call(:claims, _from, state) do
    {:reply, state.claims, state}
  end

  @impl GenServer
  def handle_call(:valid?, _from, state) do
    {:reply, state.valid?, state}
  end

  @impl GenServer
  def handle_info(:recheck_license, state) do
    lic_token_var = Application.get_env(:encrypt_beam, :license_token_env_var, "LICENSE_KEY")
    license_key = System.get_env(lic_token_var)

    case Verifier.verify(license_key, state.opts) do
      {:ok, claims} ->
        schedule_recheck(state.opts)
        {:noreply, %{state | claims: claims, valid?: true}}

      {:error, reason} ->
        Logger.error("[EncryptBeam] Runtime license re-check failed: #{inspect(reason)}")
        {:stop, {:license_invalid, reason}, state}
    end
  end

  defp schedule_recheck(opts) do
    interval =
      Keyword.get(opts, :recheck_interval_ms) ||
        Application.get_env(:encrypt_beam, :recheck_interval_ms)

    if is_integer(interval) and interval > 0 do
      Process.send_after(self(), :recheck_license, interval)
    end
  end

  # Direct delegation helpers if called outside a supervision tree
  defdelegate verify_license(license_key, opts \\ []), to: Verifier, as: :verify
  defdelegate decrypt_and_load_all(secret), to: ProtectedLoader
end
