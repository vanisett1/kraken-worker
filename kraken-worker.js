export default {
  async fetch(request) {
    if (request.method !== 'POST') {
      return new Response("Only POST requests are supported", { status: 405 });
    }

    try {
      const { body_str, nonce, endpoint } = await request.json();

      // STEP 1: Build the signature input
      const path = endpoint.replace("/derivatives", "");
      const message = body_str + nonce + path;

      // STEP 2: SHA256 hash of the message
      const sha256 = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(message)
      );

      // STEP 3: Decode the API secret from base64
      const base64Secret = "YOUR_KRAKEN_API_SECRET_BASE64";  // 🔒 Replace this!
      const rawSecret = Uint8Array.from(atob(base64Secret), c => c.charCodeAt(0));

      // STEP 4: Import HMAC key
      const key = await crypto.subtle.importKey(
        "raw",
        rawSecret,
        { name: "HMAC", hash: "SHA-512" },
        false,
        ["sign"]
      );

      // STEP 5: HMAC-SHA512 signature
      const hmac = await crypto.subtle.sign("HMAC", key, sha256);
      const signature = btoa(String.fromCharCode(...new Uint8Array(hmac)));

      return new Response(
        JSON.stringify({ signature }),
        {
          headers: { "Content-Type": "application/json" },
          status: 200
        }
      );

    } catch (err) {
      return new Response(`Error: ${err.message}`, { status: 500 });
    }
  }
};
