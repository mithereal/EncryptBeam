defmodule EncryptBeam.ProtectedLoader do
  @moduledoc """
  Decrypts AES-256-GCM secured BEAM binaries in memory, loads them into the
  Erlang VM code server, and unloads/purges them when requested.
  """
  require Logger

  @spec decrypt_and_load_all(binary()) :: {:ok, [module()]}
  def decrypt_and_load_all(encryption_secret) when is_binary(encryption_secret) do
    app_name = Application.fetch_env!(:encrypt_beam, :app_name)
    derived_key = :crypto.hash(:sha256, encryption_secret)
    encrypted_dir = Application.app_dir(app_name, "priv/encrypted_beams")

    if File.dir?(encrypted_dir) do
      loaded_modules =
        encrypted_dir
        |> File.ls!()
        |> Enum.filter(&String.ends_with?(&1, ".beam.enc"))
        |> Enum.map(fn filename ->
          file_path = Path.join(encrypted_dir, filename)
          load_single_beam(file_path, derived_key)
        end)

      {:ok, loaded_modules}
    else
      Logger.warning(
        "[ProtectedLoader] Encrypted beams directory not found: #{encrypted_dir}. Skipping."
      )

      {:ok, []}
    end
  end

  @doc """
  Purges and deletes all specified protected modules from the Erlang VM code server.
  """
  @spec unload_all([module()]) :: :ok
  def unload_all(modules) when is_list(modules) do
    Enum.each(modules, fn mod ->
      :code.purge(mod)
      :code.delete(mod)
      :code.purge(mod)
      Logger.warning("[ProtectedLoader] Unloaded protected module from VM: #{inspect(mod)}")
    end)

    :ok
  end

  defp load_single_beam(file_path, key) do
    secured_blob = File.read!(file_path)

    # Unpack blob: [IV (12 bytes) | Tag (16 bytes) | Ciphertext]
    <<iv::binary-size(12), tag::binary-size(16), ciphertext::binary>> = secured_blob

    case :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, ciphertext, iv, tag, false) do
      decrypted_beam when is_binary(decrypted_beam) ->
        module_name = extract_module_name(file_path)

        case :code.load_binary(module_name, to_charlist(file_path), decrypted_beam) do
          {:module, mod} ->
            Logger.debug("[ProtectedLoader] Loaded protected module: #{inspect(mod)}")
            mod

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
