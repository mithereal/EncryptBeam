import Config

config :encrypt_beam,
  app_name: :my_app,
  # Public key embedded in config or provided via BASE64_ED25519_PUB_KEY
  license_public_key: System.get_env("BASE64_ED25519_PUB_KEY"),
  # Env var holding the private JWK JSON (used only when signing licenses)
  priv_license_key_env_var: "PRIV_LIC_KEY_JSON",
  # Env var holding the signed license token at runtime
  license_token_env_var: "LICENSE_KEY",
  # Env var holding the >=32-byte AES-256-GCM build/runtime secret
  encryption_secret_env_var: "APP_ENCRYPTION_SECRET",
  # Keep Application boot module and any pre-boot modules unencrypted
  keep_unencrypted_modules: [MyApp.Application],
  # Fail boot in production if license is invalid; set false in dev/test
  strict_mode: config_env() == :prod
