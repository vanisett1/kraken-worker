export default {
  async fetch(request, env) {
    // Parse the input JSON array
    const inputArr = await request.json();
    const { bodyStr, nonce, pathSig } = inputArr[0];

    // Your secrets
    const API_KEY = env.KRAKEN_API_KEY;
    const API_SECRET = env.KRAKEN_API_SECRET; // base64 encoded

    // Signature: sha256(bodyStr + nonce + pathSig), then HMAC-SHA512, then base64
    const encoder = new TextEncoder();
    const sigInput = bodyStr + nonce + pathSig;

    // 1. SHA256
    const sha256 = await crypto.subtle.digest(
      "SHA-256",
      encoder.encode(sigInput)
    );

    // 2. HMAC-SHA512
    const key = await crypto.subtle.importKey(
      "raw",
      Uint8Array.from(atob(API_SECRET), c => c.charCodeAt(0)),
      { name: "HMAC", hash: "SHA-512" },
      false,
      ["sign"]
    );
    const hmac = await crypto.subtle.sign("HMAC", key, sha256);

    // 3. Base64 encode
    const signature = btoa(String.fromCharCode(...new Uint8Array(hmac)));

    // Prepare headers
    const headers = {
      "APIKey": API_KEY,
      "Authent": signature,
      "Nonce": nonce,
      "Content-Type": "application/x-www-form-urlencoded"
    };

    // Prepare endpoint
    const endpoint = "https://futures.kraken.com/derivatives/api/v3/sendorder";

    // Output JSON for n8n HTTP node
    const output = {
      url: endpoint,
      method: "POST",
      headers,
      body: bodyStr
    };

    return new Response(JSON.stringify(output), {
      headers: { "Content-Type": "application/json" }
    });
  }
}
