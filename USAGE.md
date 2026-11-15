High-Level Architecture

1. You (Vendor): Hold PRIV_LIC_KEY_JSON (your master Ed25519 private signing key) inside Cloudflare Worker Secrets and your secure local vault. You never distribute this key.
2. Build & Release Pipeline: Compile your app, embed your Ed25519 Public Key (BASE64_ED25519_PUB_KEY) into the binary, encrypt your .beam files using a per-release APP_ENCRYPTION_SECRET, and strip the plaintext .beam files.
3. First Install (Trial / Starter Key): You ship the self-hosted package with a short-lived starter LICENSE_KEY (e.g., valid for 7 or 14 days) so the user can boot the app immediately without friction.
4. Activation & Auto-Renewal (Cloudflare Worker): Before the starter key expires—or when the user enters their purchase/activation code in your app's UI—the self-hosted app calls your Cloudflare Worker. The Worker validates the customer's subscription/activation code, signs a fresh LICENSE_KEY using PRIV_LIC_KEY_JSON, and returns it to the self-hosted app.
5. Runtime Protection (EncryptBeam): Your app updates LICENSE_KEY in memory/persistent storage. EncryptBeam.LicenseWatchdog validates the new token and keeps the decrypted modules running. If the user cancels or fails to renew, the token expires and LicenseWatchdog automatically unloads the protected modules from VM memory.

### Phase 1: Master Key Generation & Build Setup (One-Time)

* Generate your master Ed25519 keypair: Run mix gen_license_key once on a secure machine.
* Save the JWK Private Key JSON (PRIV_LIC_KEY_JSON) into your password manager and upload it to Cloudflare (npx wrangler secret put PRIV_LIC_KEY_JSON).
* Copy the Base64 Public Key (BASE64_ED25519_PUB_KEY).
* Hardcode the Public Key at compile time: In your host app's config/prod.exs (not runtime.exs), embed license_public_key: "YOUR_BASE64_ED25519_PUB_KEY". Compiling the public key directly into your app prevents a self-hosted user from simply overriding an environment variable with their own keypair.
* Generate a release-specific APP_ENCRYPTION_SECRET: Run openssl rand -hex 32 to create a 64-character secret for your release build.

### Phase 2: Starter Key & Packaging for Self-Hosting

Because your users self-host via Docker, a binary release, or a VM image, you want their first boot to succeed out of the box while enforcing a strict trial window.
* Mint a short-lived Starter Key:bash
PRIV_LIC_KEY_JSON='...' mix gen_license_key --sign --issue "trial-starter" --tier "trial" --days 7

* Handle "First Install" Expiration:
* Option A (Fixed Build Window): Mint the starter key right before publishing a release image (e.g., valid for 14 days from build date).
* Option B (True First-Boot Clock): On first boot, have your app record the installed_at timestamp in its local database (e.g., SQLite/Postgres) and immediately call your Cloudflare Worker's /api/v1/trial endpoint with a generated instance_id (hardware/DB fingerprint) to receive a signed 7-day trial token tied to that specific installation.
* Build & Strip the Release:bash

* MIX_ENV=prod APP_ENCRYPTION_SECRET="your-64-char-secret" mix encrypt_beams --strip

* MIX_ENV=prod mix release

* Deliver APP_ENCRYPTION_SECRET cleanly: Include APP_ENCRYPTION_SECRET in your default docker-compose.yml or release env.sh alongside the starter LICENSE_KEY. (Note: Even though the user can see APP_ENCRYPTION_SECRET in their Docker config, they still cannot boot the app past day 7 without a valid Ed25519-signed LICENSE_KEY from your Cloudflare Worker—and if you rotate APP_ENCRYPTION_SECRET on future releases, unpaid users cannot decrypt newer versions either.)

### Phase 3: Cloudflare Worker License Server

Your Mix.Tasks.GenLicenseKey task already outputs the private key in WebCrypto JWK format (kty: "OKP", crv: "Ed25519"), which Cloudflare Workers natively support via crypto.subtle with zero external dependencies.

Cloudflare Worker Flow (POST /api/v1/activate & POST /api/v1/refresh)

1. Receive Request: Your self-hosted Elixir app sends { "activation_code": "CUST-XXXX", "instance_id": "uuid-v4" }.
2. Verify Entitlement: The Worker checks Cloudflare KV, D1, or Stripe API to confirm activation_code is active, not revoked, and within its allowed instance limit.
3. Sign Fresh Token: Using crypto.subtle.importKey("jwk", JSON.parse(env.PRIV_LIC_KEY_JSON), { name: "Ed25519" }, false, ["sign"]), the Worker builds the JSON payload ({ issue: customerEmail, tier: "pro", exp: now + 30_days }), Base64URL-encodes it, signs it with crypto.subtle.sign("Ed25519", ...), and returns "#{payload_b64}.#{sig_b64}".
4. Short-Lived Lease Window: Issue 7-day or 30-day tokens even for annual or lifetime customers, and have your Elixir app silently call /api/v1/refresh once a day. That way, if a customer disputes a charge or cancels, their license expires automatically within days without needing an inbound webhook to their firewalled self-hosted server.

### Phase 4: Self-Hosted App Activation & Renewal Loop

Inside your Elixir app, add a lightweight LicenseClient GenServer alongside EncryptBeam:
1. Persist LICENSE_KEY locally: Store the active LICENSE_KEY in your app's database or a mounted volume file (e.g., /data/license.key), and load it into System.put_env("LICENSE_KEY", token) during runtime.exs before EncryptBeam starts.
2. Frontend Activation Form: When EncryptBeam.valid?() is false (or when claims.tier == "trial"), show a banner in your UI with an input box for the user's Activation Key.
3. Hot Activation Without Restart:
   * User submits their Activation Key in your UI.
   * Your app sends it to your Cloudflare Worker and receives the signed LICENSE_KEY.
   * Your app saves the token to disk/DB, calls System.put_env("LICENSE_KEY", new_token), and calls EncryptBeam.check_now().
   * EncryptBeam.LicenseWatchdog immediately verifies the signature, decrypts the .beam.enc files into VM memory, flips EncryptBeam.valid?() to true, and broadcasts the status change to unlock the UI immediately—no container restart required.

### Summary Checklist Before Launch


1.	Embed BASE64_ED25519_PUB_KEY in config/prod.exs	Prevents users from swapping the public key via env vars

2.	Store PRIV_LIC_KEY_JSON only in Cloudflare Secrets	Master signing key never touches build artifacts or customer servers

3.	Use POST /api/v1/trial with instance_id on first boot	Prevents users from resetting their 7-day trial by re-downloading the image

4.	Issue 7–30 day rolling tokens + daily background refresh	Gives you remote revocation power over self-hosted instances

5.	Rotate APP_ENCRYPTION_SECRET on major app updates	Prevents expired users from decrypting future feature releases
