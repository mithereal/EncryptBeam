import Config

config :encrypt_beam,
  app_name: :my_app,
  license_public_key: System.get_env("BASE64_ED25519_PUB_KEY"),
  priv_license_key_env_var: "PRIV_LIC_KEY_JSON",
  license_token_env_var: "LICENSE_KEY",
  encryption_secret_env_var: "APP_ENCRYPTION_SECRET",
  # Continuous scan interval (e.g., every 15 seconds)
  scan_interval_ms: :timer.seconds(15),
  # Callback module that broadcasts status updates to your frontend
  notifier: MyApp.LicenseNotifier,
  # Keep False if you want the web frontend to stay online and show a license warning
  strict_mode: false,
  # Keep boot & frontend shell modules unencrypted so the UI can render when beams unload
  keep_unencrypted_modules: [
    MyApp.Application,
    MyApp.LicenseNotifier,
    MyAppWeb.Endpoint,
    MyAppWeb.Router,
    MyAppWeb.LicenseLive
  ]
