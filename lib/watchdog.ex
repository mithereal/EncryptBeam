defmodule EncryptBeam.LicenseWatchdog do
  @moduledoc """
  Continuously monitors license validity on a configurable interval.
  If the license expires or becomes invalid, it unloads all decrypted BEAM
  modules from memory, logs a console alert, updates a fast status flag, and
  notifies an optional callback module for frontend display.
  """
  use GenServer
  require Logger

  alias EncryptBeam.{ProtectedLoader, Verifier}

  @flag_key {__MODULE__, :status}
  @default_scan_interval_ms 30_000

  @type status_payload :: %{
          valid?: boolean(),
          reason: atom() | nil,
          message: String.t(),
          claims: map() | nil,
          checked_at: DateTime.t()
        }

  @doc """
  Optional callback behaviour for pushing license status changes to a frontend
  (e.g., via Phoenix.PubSub or LiveView).
  """
  @callback on_license_status_change(status_payload()) :: any()

  # --- Public Frontend / Host App API ---

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Fast, non-blocking check returning `true` if the license is currently valid
  and protected beams are loaded, or `false` otherwise.
  """
  @spec valid?() :: boolean()
  def valid? do
    status().valid?
  end

  @doc """
  Returns the full license status map (including `:valid?`, `:reason`, `:message`,
  `:claims`, and `:checked_at`) for rendering in a frontend UI or API.
  """
  @spec status() :: status_payload()
  def status do
    :persistent_term.get(@flag_key, %{
      valid?: false,
      reason: :not_initialized,
      message: "License watchdog has not completed initial check.",
      claims: nil,
      checked_at: DateTime.utc_now()
    })
  end

  @doc """
  Forces an immediate license scan outside the normal timer interval.
  """
  @spec check_now() :: status_payload()
  def check_now do
    GenServer.call(__MODULE__, :check_now)
  end

  # --- GenServer Callbacks ---

  @impl GenServer
  def init(opts) do
    state = %{
      opts: opts,
      loaded_modules: [],
      scan_interval_ms:
        Keyword.get(opts, :scan_interval_ms) ||
          Application.get_env(:encrypt_beam, :scan_interval_ms, @default_scan_interval_ms),
      notifier:
        Keyword.get(opts, :notifier) ||
          Application.get_env(:encrypt_beam, :notifier)
    }

    # Perform synchronous initial verification and beam loading before supervision continues
    new_state = perform_scan(state, true)
    schedule_next_scan(new_state.scan_interval_ms)

    {:ok, new_state}
  end

  @impl GenServer
  def handle_call(:check_now, _from, state) do
    new_state = perform_scan(state, false)
    {:reply, status(), new_state}
  end

  @impl GenServer
  def handle_info(:scan_license, state) do
    new_state = perform_scan(state, false)
    schedule_next_scan(new_state.scan_interval_ms)
    {:noreply, new_state}
  end

  # --- Internal Verification & Unload Logic ---

  defp perform_scan(state, initial_boot?) do
    lic_token_var = Application.get_env(:encrypt_beam, :license_token_env_var, "LICENSE_KEY")
    license_key = System.get_env(lic_token_var)

    enc_secret_var =
      Application.get_env(:encrypt_beam, :encryption_secret_env_var, "APP_ENCRYPTION_SECRET")

    encryption_secret = System.get_env(enc_secret_var)

    strict_mode =
      Keyword.get(
        state.opts,
        :strict_mode,
        Application.get_env(:encrypt_beam, :strict_mode, true)
      )

    case Verifier.verify(license_key, state.opts) do
      {:ok, claims} ->
        handle_valid_license(state, claims, encryption_secret, enc_secret_var)

      {:error, reason} ->
        if initial_boot? and strict_mode do
          print_console_alert(reason)

          raise "[EncryptBeam] CRITICAL: Startup license verification failed (#{inspect(reason)})."
        end

        handle_invalid_license(state, reason)
    end
  end

  defp handle_valid_license(state, claims, encryption_secret, enc_secret_var) do
    loaded_modules =
      if state.loaded_modules == [] do
        if is_nil(encryption_secret) or byte_size(encryption_secret) < 32 do
          raise "[EncryptBeam] CRITICAL: Missing or invalid #{enc_secret_var} (must be >= 32 bytes)."
        end

        Logger.info(
          "[EncryptBeam] License valid (Issue: #{claims.issue}, Tier: #{claims.tier}). Loading beams..."
        )

        {:ok, mods} = ProtectedLoader.decrypt_and_load_all(encryption_secret)
        mods
      else
        state.loaded_modules
      end

    payload = %{
      valid?: true,
      reason: nil,
      message: "License active (#{claims.tier} tier)",
      claims: claims,
      checked_at: DateTime.utc_now()
    }

    update_status_and_notify(payload, state.notifier)
    %{state | loaded_modules: loaded_modules}
  end

  defp handle_invalid_license(state, reason) do
    # 1. Unload beams if any are currently loaded in VM memory
    if state.loaded_modules != [] do
      ProtectedLoader.unload_all(state.loaded_modules)
    end

    # 2. Display prominent console message
    print_console_alert(reason)

    # 3. Update frontend flag and trigger optional notifier module
    payload = %{
      valid?: false,
      reason: reason,
      message: format_human_message(reason),
      claims: nil,
      checked_at: DateTime.utc_now()
    }

    update_status_and_notify(payload, state.notifier)
    %{state | loaded_modules: []}
  end

  defp update_status_and_notify(payload, notifier) do
    previous = :persistent_term.get(@flag_key, nil)
    :persistent_term.put(@flag_key, payload)

    # Notify frontend module whenever validity changes or license remains invalid
    if notifier && (is_nil(previous) or previous.valid? != payload.valid? or not payload.valid?) do
      try do
        notifier.on_license_status_change(payload)
      rescue
        e ->
          Logger.error(
            "[EncryptBeam] Notifier #{inspect(notifier)} raised an error: #{inspect(e)}"
          )
      end
    end
  end

  defp print_console_alert(reason) do
    msg = """
    ====================================================================
    [EncryptBeam ALERT] LICENSE INVALID OR EXPIRED (#{inspect(reason)})
    Protected BEAM modules have been unloaded from VM memory.
    Please update LICENSE_KEY with a valid signed token to restore access.
    ====================================================================
    """

    IO.puts(:stderr, IO.ANSI.red() <> msg <> IO.ANSI.reset())
    Logger.error("[EncryptBeam] License invalid (#{inspect(reason)}). Protected BEAMs unloaded.")
  end

  defp format_human_message(:license_expired), do: "Your application license has expired."
  defp format_human_message(:missing_license), do: "No license key was provided."
  defp format_human_message(:invalid_signature), do: "The license signature is invalid."
  defp format_human_message(reason), do: "License check failed (#{reason})."

  defp schedule_next_scan(interval_ms) when is_integer(interval_ms) and interval_ms > 0 do
    Process.send_after(self(), :scan_license, interval_ms)
  end
end
