import { bech32m } from "bech32";

export async function generateRandomIDwithHMACinBech32m(
  signing_key: CryptoKey,
  prefix: string,
  id_byte_length: number = 8,
  output_length_limit: number = 63,
  random_id?: Uint8Array
) {
  if (!random_id) {
    random_id = crypto.getRandomValues(new Uint8Array(id_byte_length));
  }

  const random_id_signature = new Uint8Array(
    await crypto.subtle.sign("HMAC", signing_key, random_id)
  );

  const random_id_and_signature = new Uint8Array(
    random_id.length + random_id_signature.length
  );
  random_id_and_signature.set(random_id);
  random_id_and_signature.set(random_id_signature, random_id.length);

  const random_id_and_signature_bech32m = bech32m.encode(
    prefix,
    bech32m.toWords(random_id_and_signature),
    output_length_limit
  );

  return random_id_and_signature_bech32m;
}

export async function verifyRandomIDwithHMACinBech32m(
  signing_key: CryptoKey,
  random_id_and_signature_bech32m: string,
  hash_algo: string = "SHA-1",
  expected_prefix?: string
): Promise<boolean> {
  const key_length =
    signing_key.algorithm.name === "HMAC" && hash_algo === "SHA-1"
      ? 20
      : signing_key.algorithm.name === "HMAC" && hash_algo === "SHA-512"
      ? 64
      : null;
  if (key_length === null) {
    throw new Error("Unsupported HMAC algorithm or key");
  }

  try {
    const { prefix, words } = bech32m.decode(random_id_and_signature_bech32m);

    if (expected_prefix && expected_prefix !== prefix) throw new Error("Prefix mismatch");

    const random_id_and_signature = new Uint8Array(bech32m.fromWords(words));
    const random_id = random_id_and_signature.slice(0, -key_length);

    const real_signature = await generateRandomIDwithHMACinBech32m(
      signing_key,
      prefix,
      random_id.byteLength,
      random_id_and_signature_bech32m.length + prefix.length,
      random_id
    );
    if(typeof crypto.subtle.timingSafeEqual) {
      const real_signature_bytes = new TextEncoder().encode(real_signature);
      const random_id_and_signature_bech32m_bytes = new TextEncoder().encode(random_id_and_signature_bech32m);
      return crypto.subtle.timingSafeEqual(real_signature_bytes, random_id_and_signature_bech32m_bytes);
    }
    else if (real_signature === random_id_and_signature_bech32m) {
      console.warn("crypto.subtle.timingSafeEqual is not available, using string comparison instead");
      return true;
    }
  }
  catch (e) {
    console.error(e);
    return false;
  }

  return false;
}
