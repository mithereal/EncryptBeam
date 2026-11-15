defmodule EncryptBeam.ProtectedLoader do
  @moduledoc """
  Handles decryption of AES-256-GCM secured BEAM binaries in memory and
  dynamically loads them into the Erlang VM code server at runtime.
  """
  require Logger

  @spec decrypt_and_load_all(binary()) :: :ok | {:error, term()}
  app_name = Application.fetch_env!(:encrypt_beam, :app_name)
  def decrypt_and_load_all(encryption_key) do
    derived_key = :crypto.hash(:sha256, encryption_key)
    encrypted_dir = Application.app_dir(app_name, "priv/encrypted_beams")

    if File.dir?(encrypted_dir) do
      encrypted_dir
      |> File.ls!()
      |> Enum.filter(&String.ends_with?(&1, ".beam.enc"))
      |> Enum.each(fn filename ->
        file_path = Path.join(encrypted_dir, filename)
        load_single_beam(file_path, derived_key)
      end)

      :ok
    else
      Logger.warning("[ProtectedLoader] Encrypted beams directory not found: #{encrypted_dir}. Skipping.")
      :ok
    end


  end

  defp load_single_beam(file_path, key) do
    secured_blob = File.read!(file_path)

    # Unpack blob: [IV (12 bytes) | Tag (16 bytes) | Ciphertext]
    <<iv::binary-size(12), tag::binary-size(16), ciphertext::binary>> = secured_blob

    case :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, ciphertext, <<>>, tag, false) do
      decrypted_beam when is_binary(decrypted_beam) ->
        module_name = extract_module_name(file_path)

        case :code.load_binary(module_name, to_charlist(file_path), decrypted_beam) do
          {:module, mod} ->
            Logger.debug("[ProtectedLoader] Successfully loaded protected module: #{inspect(mod)}")
          {:error, reason} ->
            raise "[ProtectedLoader] Failed to load module #{inspect(module_name)} into VM: #{inspect(reason)}"
        end

      :error ->
        raise "[ProtectedLoader] Cryptographic authentication failed for #{file_path}! Binary may be corrupted or tampered with."
    end


  end

  defp extract_module_name(file_path) do
    file_path
    |> Path.basename()
    |> Path.rootname(".enc")
    |> Path.rootname(".beam")
    |> String.to_atom()
  end
end