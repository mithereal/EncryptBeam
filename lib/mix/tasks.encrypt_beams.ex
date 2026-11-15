defmodule Mix.Tasks.EncryptBeams do
  @shortdoc "Compiles and encrypts production BEAM binaries with AES-256-GCM"

  @moduledoc """
  Production-grade mix task that compiles your Elixir application, reads all generated
  .beam files, encrypts them using authenticated AES-256-GCM encryption, and outputs
  them to priv/encrypted_beams/.

  Usage

    APP_ENCRYPTION_SECRET="your-secure-build-secret" mix encrypt_beams


  """

  use Mix.Task

  @impl Mix.Task
  def run(args) do
    # Ensure compilation is up-to-date in production mode
    Mix.env(:prod)
    Mix.Task.run("compile")

    secret = System.get_env("APP_ENCRYPTION_SECRET")
    if is_nil(secret) or byte_size(secret) < 32 do
      Mix.raise("ERROR: APP_ENCRYPTION_SECRET environment variable must be set and at least 32 bytes long.")
    end

    # Derive a robust 32-byte encryption key using SHA-256
    encryption_key = :crypto.hash(:sha256, secret)

    build_dir = Mix.Project.compile_path()
    output_dir = Path.join(Mix.Project.app_path(), "priv/encrypted_beams")
    File.mkdir_p!(output_dir)

    Mix.shell().info([:green, "=== Encrypting BEAM binaries for production deployment ==="])

    Path.wildcard("#{build_dir}/*.beam")
    |> Enum.each(fn beam_path ->
      filename = Path.basename(beam_path)
      plain_binary = File.read!(beam_path)

      # Encrypt with AES-256-GCM
      {ciphertext, iv, tag} = encrypt_payload(plain_binary, encryption_key)

      # Format: [IV (12 bytes) | Tag (16 bytes) | Ciphertext]
      secured_blob = <<iv::binary-size(12), tag::binary-size(16), ciphertext::binary>>

      dest_path = Path.join(output_dir, "#{filename}.enc")
      File.write!(dest_path, secured_blob)
      Mix.shell().info("Encrypted: #{filename} -> #{Path.basename(dest_path)}")
    end)

    Mix.shell().info([:green, "\nSuccessfully encrypted all BEAM binaries into #{output_dir}\n"])


  end

  defp encrypt_payload(plaintext, key) do
    iv = :crypto.strong_rand_bytes(12)
    # Using AES-256-GCM authenticated encryption (AAD is empty binary)
    {ciphertext, tag} = :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, plaintext, <<>>, true)
    {ciphertext, iv, tag}
  end
end