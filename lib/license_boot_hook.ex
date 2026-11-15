defmodule EncryptBeam.LicenseBootHook do
  @moduledoc """
  Validates the signed license token and triggers in-memory decryption
  of protected BEAM binaries.
  """
  require Logger
  alias EncryptBeam.{ProtectedLoader, Verifier}

  @spec verify_and_boot!(keyword()) :: {:ok, map()} | :ok
  def verify_and_boot!(opts \\ []) do
    lic_token_var = Application.get_env(:encrypt_beam, :license_token_env_var, "LICENSE_KEY")
    license_key = System.get_env(lic_token_var)

    enc_secret_var =
      Application.get_env(:encrypt_beam, :encryption_secret_env_var, "APP_ENCRYPTION_SECRET")

    encryption_secret = System.get_env(enc_secret_var)

    strict_mode =
      Keyword.get(opts, :strict_mode, Application.get_env(:encrypt_beam, :strict_mode, true))

    case Verifier.verify(license_key, opts) do
      {:ok, claims} ->
        if is_nil(encryption_secret) or byte_size(encryption_secret) < 32 do
          raise "[LicenseBootHook] CRITICAL: Missing or invalid #{enc_secret_var} (must be >= 32 bytes)."
        end

        Logger.info(
          "[LicenseBootHook] License verified for Issue: #{claims.issue} (Tier: #{claims.tier})"
        )

        :ok = ProtectedLoader.decrypt_and_load_all(encryption_secret)
        {:ok, claims}

      {:error, reason} ->
        if strict_mode do
          raise "[LicenseBootHook] CRITICAL: License verification failed! Reason: #{inspect(reason)}"
        else
          Logger.warning(
            "[LicenseBootHook] Non-strict mode: License verification failed (#{inspect(reason)}), skipping encrypted beam load."
          )

          :ok
        end
    end
  end
end
