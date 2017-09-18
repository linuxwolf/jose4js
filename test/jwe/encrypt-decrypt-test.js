/*!
 *
 */

const assert = require("chai").assert,
      UTF8 = require("../../lib/util/utf8");

const JWA = require("../../lib/jwa");
const JWE = {
  encrypt: require("../../lib/jwe/encrypt").encrypt,
  decrypt: require("../../lib/jwe/decrypt").decrypt
};

describe("JWE", () => {
  it("roundtrip dir/A128GCM", async () => {
    let opts, cipher;
    cipher = JWA.cipher("A128GCM");
    opts = await cipher.generateKey();

    let plaintext = "hello there";
    let result = await JWE.encrypt(opts, plaintext);
    assert.ok(result);
    let encrypted = result;
    result = await JWE.decrypt(opts, encrypted);
    assert.ok(result);
    assert.ok(result.plaintext);
    assert.strictEqual(UTF8.decode(result.plaintext), plaintext);
  });

  it("roundtrip A128KW/A128GCM", async () => {
    let opts, wrappingCipher, cipher;
    wrappingCipher = JWA.cipher("A128KW");
    cipher = JWA.cipher("A128GCM");
    opts = await wrappingCipher.generateKey();
    opts = await cipher.generateKey(opts);

    let plaintext = "hello there";
    let result = await JWE.encrypt(opts, plaintext);
    assert.ok(result);
    let encrypted = result;
    result = await JWE.decrypt(opts, encrypted);
    assert.ok(result);
    assert.ok(result.plaintext);
    assert.strictEqual(UTF8.decode(result.plaintext), plaintext);
  });
});
