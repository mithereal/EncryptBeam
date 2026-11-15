defmodule EncryptBeam.LicenseBootHook do
  @moduledoc """
  Hooks the binary decryption/loading sequence directly into the application's
  license server validation workflow. If a valid signed license key (or server confirmation)
  is present and verified, it unlocks the decryption key and loads protected modules.
  """
  require Logger
  alias EncryptBeam.Verifier
  alias EncryptBeam.ProtectedLoader


  @doc """
  Invoked during application boot. Validates the license token, derives the cryptographic
  decryption key from the validated license claims or environment secret, and loads binaries.
  """
  def verify_and_boot! do
    lic_key_var = Application.fetch_env!(:encrypt_beam, :priv_license_key_env_var)
    license_key = System.get_env(lic_key_var)

    enc_key_var = Application.fetch_env!(:encrypt_beam, :encryption_salt_env_var)
    enc_salt = System.get_env(enc_key_var)

    case Verifier.verify(license_key) do
      {:ok, claims} ->
        Logger.info("[LicenseBootHook] License verified successfully for Issue: #{claims.issue} (Tier: #{claims.tier})")

        # Derive decryption key using the license token + a system secret salt
        decryption_secret = "#{license_key}:#{claims.issue}:#{enc_salt}"

        # Decrypt and load protected modules into the BEAM VM
        ProtectedLoader.decrypt_and_load_all(decryption_secret)

      {:error, reason} ->
        if Mix.env() == :prod do
          raise "[LicenseBootHook] CRITICAL: Failed to verify production license for encrypted binaries! Reason: #{inspect(reason)}"
        else
          Logger.warning("[LicenseBootHook] Development mode: License verification failed (#{inspect(reason)}), falling back to unencrypted build state.")
        end
    end


  end
end