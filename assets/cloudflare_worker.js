export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method !== "POST") {
      return jsonResponse({ error: "method_not_allowed" }, 405);
    }

    try {
      const body = await request.json();

      if (url.pathname === "/api/v1/trial") {
        return await handleTrial(body, env);
      }

      if (url.pathname === "/api/v1/activate") {
        return await handleActivate(body, env);
      }

      return jsonResponse({ error: "not_found" }, 404);
    } catch (err) {
      return jsonResponse({ error: "bad_request", detail: err.message }, 400);
    }
  },
};

/**
 * Issues a one-time 7-day trial token bound to the self-hosted instance_id.
 * Prevents users from resetting their trial simply by restarting or re-pulling Docker.
 */
async function handleTrial({ instance_id }, env) {
  if (!instance_id || typeof instance_id !== "string" || instance_id.length < 16) {
    return jsonResponse({ error: "invalid_instance_id" }, 400);
  }

  const trialKey = `trial:${instance_id}`;
  const existing = await env.LICENSES_KV.get(trialKey, { type: "json" });

  const now = Math.floor(Date.now() / 1000);
  let exp;

  if (existing) {
    // Reuse original expiration timestamp so reinstalling doesn't extend the trial
    exp = existing.exp;
    if (now >= exp) {
      return jsonResponse({ error: "trial_expired", message: "7-day trial has ended." }, 403);
    }
  } else {
    exp = now + 7 * 86400; // 7 days from first install
    await env.LICENSES_KV.put(trialKey, JSON.stringify({ created_at: now, exp }));
  }

  const token = await signLicenseToken(
    {
      issue: `trial:${instance_id.slice(0, 8)}`,
      tier: "trial",
      exp,
    },
    env.PRIV_LIC_KEY_JSON
  );

  return jsonResponse({ license_key: token, tier: "trial", exp });
}

/**
 * Validates a customer's activation code (used for both initial activation
 * and daily background rolling renewals).
 */
async function handleActivate({ activation_code, instance_id }, env) {
  if (!activation_code || !instance_id) {
    return jsonResponse({ error: "missing_parameters" }, 400);
  }

  const recordKey = `code:${activation_code.trim()}`;
  const record = await env.LICENSES_KV.get(recordKey, { type: "json" });

  if (!record || !record.active) {
    return jsonResponse({ error: "invalid_or_revoked_license" }, 403);
  }

  // Enforce max self-hosted instances per license key
  const instances = Array.isArray(record.instances) ? record.instances : [];
  if (!instances.includes(instance_id)) {
    const max = record.max_instances || 1;
    if (instances.length >= max) {
      return jsonResponse(
        { error: "instance_limit_reached", message: `Max ${max} self-hosted instance(s) allowed.` },
        403
      );
    }
    instances.push(instance_id);
    record.instances = instances;
    await env.LICENSES_KV.put(recordKey, JSON.stringify(record));
  }

  // Issue a rolling 14-day lease token (Elixir app refreshes this daily)
  const leaseDays = record.lease_days || 14;
  const exp = Math.floor(Date.now() / 1000) + leaseDays * 86400;

  const token = await signLicenseToken(
    {
      issue: record.email,
      tier: record.tier || "pro",
      exp,
    },
    env.PRIV_LIC_KEY_JSON
  );

  return jsonResponse({
    license_key: token,
    tier: record.tier || "pro",
    exp,
  });
}

/**
 * Signs claims with the Ed25519 JWK stored in PRIV_LIC_KEY_JSON
 * matching EncryptBeam.Verifier's exact `payload_b64.sig_b64` wire format.
 */
async function signLicenseToken(claims, jwkJsonString) {
  const jwk = JSON.parse(jwkJsonString);
  const cryptoKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "Ed25519" },
    false,
    ["sign"]
  );

  const encoder = new TextEncoder();
  const payloadJson = JSON.stringify(claims);
  const payloadB64 = base64UrlEncode(encoder.encode(payloadJson));

  // Sign the ASCII bytes of payloadB64 (matches :crypto.sign(:eddsa, :none, payload_b64, ...))
  const signatureBuffer = await crypto.subtle.sign(
    "Ed25519",
    cryptoKey,
    encoder.encode(payloadB64)
  );

  const sigB64 = base64UrlEncode(new Uint8Array(signatureBuffer));
  return `${payloadB64}.${sigB64}`;
}

function base64UrlEncode(uint8Array) {
  let binary = "";
  for (let i = 0; i < uint8Array.byteLength; i++) {
    binary += String.fromCharCode(uint8Array[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
