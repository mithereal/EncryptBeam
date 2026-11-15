defmodule EncryptBeam.BeamFilter do
  @moduledoc false

  @encrypt_beam_modules [
    EncryptBeam,
    EncryptBeam.BeamFilter,
    EncryptBeam.LicenseBootHook,
    EncryptBeam.LicenseWatchdog,
    EncryptBeam.ProtectedLoader,
    EncryptBeam.Verifier
  ]

  @doc """
  Returns paths to all `.beam` files in `build_dir` except essential boot,
  watchdog, notifier, and user-configured unencrypted modules.
  """
  @spec encryptable_beams(Path.t()) :: [Path.t()]
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

  @doc """
  Returns the full list of module atoms that must remain unencrypted on disk
  so the VM, supervision tree, license watchdog, and frontend notifier can run.
  """
  @spec boot_modules() :: [module()]
  def boot_modules do
    app_mod =
      case Keyword.get(Mix.Project.get().application(), :mod) do
        {mod, _args} -> [mod]
        _ -> []
      end

    notifier_mod =
      case Application.get_env(:encrypt_beam, :notifier) do
        mod when is_atom(mod) and not is_nil(mod) -> [mod]
        _ -> []
      end

    extra_keep = Application.get_env(:encrypt_beam, :keep_unencrypted_modules, [])

    Enum.uniq(@encrypt_beam_modules ++ app_mod ++ notifier_mod ++ extra_keep)
  end
end
