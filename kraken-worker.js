export default {
  async fetch(request) {
    if (request.method !== 'POST') {
      return new Response("Only POST requests are supported", { status: 405 });
    }

    try {
      // Match the input fields from your JSON
      const { bodyStr, nonce, pathSig } = await request.json();

      // Combine into Kraken signature input
      const sigInput = bodyStr + nonce + pathSig;

      // SHA256 hash of the full message
      const sha256 = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(sigInput)
      );

      // Secure secret loaded from Cloudflare environment secret
      const base64Secret = globalThis.KRAKEN_API_SECRET_BASE64;

      // Decode the base64 secret into binary
      const rawSecret = Uint8Array.from(atob(base64Secret), c => c.charCodeAt(0));

      // Import HMAC key for SHA-512
      const key = await crypto.subtle.importKey(
        "raw",
        rawSecret,
        { name: "HMAC", hash: "SHA-512" },
        false,
        ["sign"]
      );

      // Generate HMAC signature
      const hmac = await crypto.subtle.sign("HMAC", key, sha256);

      // Base64 encode the output
      const signature = btoa(String.fromCharCode(...new Uint8Array(hmac)));

      return new Response(
        JSON.stringify({ signature }),
        {
          headers: { "Content-Type": "application/json" },
          status: 200
        }
      );

    } catch (err) {
      return new Response(
        JSON.stringify({ error: err.message }),
        { status: 500 }
      );
    }
  }
};
