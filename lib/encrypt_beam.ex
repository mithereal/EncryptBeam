defmodule EncryptBeam do
  @moduledoc """
  Compiles encrypts and decrypts production BEAM binaries with AES-256-GCM.
  """

  defdelegate loader, to: EncryptBeam.ProtectedLoader
  defdelegate hook, to: EncryptBeam.LicenseBootHook
  defdelegate verifier, to: EncryptBeam.Verifier
end
