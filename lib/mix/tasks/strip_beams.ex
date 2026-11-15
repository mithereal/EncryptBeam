defmodule Mix.Tasks.StripBeams do
  @shortdoc "Removes plaintext .beam files that have been encrypted"

  @moduledoc """
  Deletes unencrypted `.beam` files from the build directory for all modules
  that have a matching `.beam.enc` file in `priv/encrypted_beams/`.

  ## Usage

      mix strip_beams
  """

  use Mix.Task

  @impl Mix.Task
  def run(_args) do
    Mix.Task.run("app.config")

    build_dir = Mix.Project.compile_path()
    encrypted_dir = Path.join(Mix.Project.app_path(), "priv/encrypted_beams")

    if !File.dir?(encrypted_dir) do
      Mix.raise(
        "Encrypted beams directory not found at #{encrypted_dir}. Run `mix encrypt_beams` first."
      )
    end

    encrypted_set =
      encrypted_dir
      |> File.ls!()
      |> Enum.filter(&String.ends_with?(&1, ".beam.enc"))
      |> MapSet.new(&String.trim_trailing(&1, ".enc"))

    removed_count =
      build_dir
      |> EncryptBeam.BeamFilter.encryptable_beams()
      |> Enum.reduce(0, fn beam_path, acc ->
        filename = Path.basename(beam_path)

        if MapSet.member?(encrypted_set, filename) do
          File.rm!(beam_path)
          Mix.shell().info([:yellow, "Stripped plaintext BEAM: #{filename}"])
          acc + 1
        else
          acc
        end
      end)

    Mix.shell().info([:green, "Removed #{removed_count} unencrypted BEAM files."])
  end
end
