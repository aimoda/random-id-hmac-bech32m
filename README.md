# random-id-hmac-bech32m

This module allows you to generate random tokens/IDs, and verify them later with HMAC. Think of this like a checksum that you can be reasonable confident was generated on your service.

Not cryptographically audited. Likely vulnerable to timing attacks, which may or may not be a concern for your use-case.

## Example

### Installing

#### Installing with npm

```sh
npm i @aimoda/random-id-hmac-bech32m
```

#### Installing with yarn

```sh
yarn add @aimoda/random-id-hmac-bech32m
```

### Usage with JavaScript

```javascript
const key = crypto.getRandomValues(new Uint8Array(20)); // 20*8 = 160 for SHA-1
const importedKey = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-1' }, true, ['sign']);
const encoded_result = await generateRandomIDwithHMACinBech32m(importedKey, "npm", 8, 63); // Generate a 64-bit ID with the prefix "npm", and ensure it doesn't go over 63 characters.
console.log(encoded_result); // Example: npm1jfmq9ulpljh2wx4sw5cwzrvlv3gcczarv7yts52mxfgc6t23pqr

const validated_result = await verifyRandomIDwithHMACinBech32m(importedKey, encoded_result);
console.log(validated_result); // Example: true
```

### Usage with Cloudflare Workers

```toml
name = "download-worker-dev"
main = "./src/index.ts"
compatibility_date = "2023-02-15"

[[unsafe.bindings]]
type = "secret_key"
name = "DOWNLOAD_KEY"
format = "raw"
algorithm = { name = "HMAC", hash = "SHA-1" }
usages = ["sign"]
# openssl rand -base64 20
key_base64 = "6ZuAbhvUNnfx1wUFNb6p7716mnQ="
```

```typescript
interface Env {
    DOWNLOAD_KEY: CryptoKey
}

export default {
    async fetch(request: Request, env: Env) {
        const dl_key = await generateRandomIDwithHMACinBech32m(env.DOWNLOAD_KEY, "dl", 20, 90);
        return new Response(dl_key);
    }
}
```

Thanks to [@KianNH](https://github.com/KianNH) for his [blog on using CryptoKey bindings](https://kian.org.uk/cryptokey-bindings-in-cloudflare-workers-importkey-at-publish-time/).
