defmodule EncryptBeam.BeamFilter do
  @moduledoc false

  @doc """
  Returns paths to all `.beam` files in `build_dir` except the host application's
  Application module and any modules configured in `:keep_unencrypted_modules`.
  """
  def encryptable_beams(build_dir) do
    keep_modules = boot_modules()

    Path.wildcard(Path.join(build_dir, "*.beam"))
    |> Enum.reject(fn beam_path ->
      mod_name =
        beam_path
        |> Path.basename(".beam")
        |> String.to_atom()

      mod_name in keep_modules
    end)
  end

  def boot_modules do
    app_mod =
      case Keyword.get(Mix.Project.get().application(), :mod) do
        {mod, _args} -> [mod]
        _ -> []
      end

    extra_keep = Application.get_env(:encrypt_beam, :keep_unencrypted_modules, [])
    Enum.uniq(app_mod ++ extra_keep)
  end
end
