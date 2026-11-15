defmodule EncryptBeam.Verifier do
  @moduledoc """
  Verifies Ed25519-signed license keys and decrypts session/tenant claims.
  """

  @default_public_key_b64 System.get_env("PMS_LICENSE_KEY") || "REPLACE_WITH_YOUR_32_BYTE_BASE64_ED25519_PUBLIC_KEY"

  @spec verify(String.t() | nil, keyword()) :: {:ok, map()} | {:error, atom()}
  def verify(license_key, opts \\ [])

  def verify(license_key, opts) when is_binary(license_key) and license_key != "" do
    with [payload_b64, sig_b64] <- String.split(String.trim(license_key), ".", parts: 2),
         {:ok, sig_bytes} <- Base.url_decode64(sig_b64, padding: false),
         {:ok, pub_key_bytes} <- decode_public_key(opts),
         true <- verify_ed25519(payload_b64, sig_bytes, pub_key_bytes),
         {:ok, payload_json} <- Base.url_decode64(payload_b64, padding: false),
         {:ok, raw_claims} <- Jason.decode(payload_json),
         :ok <- check_expiration(raw_claims["exp"]) do
      {:ok,
        %{
          tenant_id: raw_claims["tenant_id"],
          domain: raw_claims["domain"],
          tier: raw_claims["tier"],
          exp: raw_claims["exp"]
        }}
    else
      false -> {:error, :invalid_signature}
      {:error, reason} -> {:error, reason}
      _ -> {:error, :malformed_license}
    end
  end

  def verify(_license_key, _opts), do: {:error, :missing_license}

  defp verify_ed25519(message, signature, public_key)
       when byte_size(signature) == 64 and byte_size(public_key) == 32 do
    :crypto.verify(:eddsa, :none, message, signature, [public_key, :ed25519])
  end

  defp verify_ed25519(_message, _signature, _public_key), do: false

  defp decode_public_key(opts) do
    b64 =
      Keyword.get(opts, :public_key) ||
        Application.get_env(:ash_phoenix_starter, :license_public_key) ||
        @default_public_key_b64

    case Base.decode64(String.trim(b64)) do
      {:ok, key} when byte_size(key) == 32 -> {:ok, key}
      _ -> {:error, :invalid_public_key}
    end
  end

  defp check_expiration(nil), do: :ok

  defp check_expiration(exp) when is_integer(exp) do
    if System.system_time(:second) <= exp, do: :ok, else: {:error, :license_expired}
  end

  defp check_expiration(_), do: {:error, :invalid_expiration}
end