include Config

config :encrypt_beam,
  app_name: :my_app,
  priv_license_key_env_var: "PRIV_LIC_KEY_JSON",
  encryption_salt_env_var: "ENC_SALT"