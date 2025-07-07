export default {
  async fetch(request) {
    if (request.method !== 'POST') {
      return new Response("Only POST requests are supported", { status: 405 });
    }

    try {
      const { body_str, nonce, endpoint } = await request.json();

      const path = endpoint.replace("/derivatives", "");
      const message = body_str + nonce + path;

      const sha256 = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(message)
      );

      const base64Secret = globalThis.KRAKEN_API_SECRET_BASE64;
      const rawSecret = Uint8Array.from(atob(base64Secret), c => c.charCodeAt(0));

      const key = await crypto.subtle.importKey(
        "raw",
        rawSecret,
        { name: "HMAC", hash: "SHA-512" },
        false,
        ["sign"]
      );

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
