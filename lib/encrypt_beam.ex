defmodule EncryptBeam do
  @moduledoc """
  Supervision tree child that verifies Ed25519-signed license keys, loads
  AES-256-GCM protected BEAM binaries, and continuously monitors validity.
  """

  alias EncryptBeam.{LicenseWatchdog, ProtectedLoader, Verifier}

  defdelegate child_spec(opts), to: LicenseWatchdog
  defdelegate start_link(opts \\ []), to: LicenseWatchdog
  defdelegate valid?, to: LicenseWatchdog
  defdelegate status, to: LicenseWatchdog
  defdelegate check_now, to: LicenseWatchdog

  def claims do
    status().claims
  end

  defdelegate verify_license(license_key, opts \\ []), to: Verifier, as: :verify
  defdelegate decrypt_and_load_all(secret), to: ProtectedLoader
  defdelegate unload_all(modules), to: ProtectedLoader
end
