# EncryptBeam

**Encrypt Beam**


## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `encrypt_beam` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:encrypt_beam, "~> 0.1.0"}
  ]
end

defmodule AshPhoenixStarter.Application do
  use Application

  def start(_type, _args) do
    # 1. Validate license & decrypt/load secure BEAM binaries into memory
    AshPhoenixStarter.Security.LicenseBootHook.verify_and_boot!()

    children = [
      # ... your normal supervision tree (Telemetry, Repos, Endpoints, etc.)
    ]

    Supervisor.start_link(children, strategy: :one_for_one)
  end
end
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at <https://hexdocs.pm/encrypt_beam>.

