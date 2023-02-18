import { generateRandomIDwithHMACinBech32m, verifyRandomIDwithHMACinBech32m } from '../src';

import { bech32m } from 'bech32';


describe('generateRandomIDwithHMACinBech32m', () => {
  it('generates a valid Bech32m string', async () => {
    const key = crypto.getRandomValues(new Uint8Array(20)); // 20*8 = 160 for SHA-1
    const importedKey = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-1' }, true, ['sign']);

    const prefix = 'myprefix';
    const idByteLength = 8;
    const outputLengthLimit = 63;

    const result = await generateRandomIDwithHMACinBech32m(importedKey, prefix, idByteLength, outputLengthLimit);

    const { prefix: decodedPrefix, words } = bech32m.decode(result);
    const decoded = new Uint8Array(bech32m.fromWords(words));

    // Check that the prefix is correct
    expect(decodedPrefix).toEqual(prefix);

    // Check that the length of the decoded array matches the byte length
    expect(decoded.length).toEqual(idByteLength);

    // Check that the length of the encoded result is within the output length limit
    expect(result.length).toBeLessThanOrEqual(outputLengthLimit);
  });
});
