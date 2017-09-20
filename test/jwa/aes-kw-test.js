/*!
 *
 */

const assert = require("chai").assert;

const AESKW = require("../../lib/jwa/aes-kw");
const AESGCM = require("../../lib/jwa/aes-gcm"),
      BASE64 = require("../../lib/util/base64"),
      webcrypto = require("../../lib/util/webcrypto");

describe("'AES-KW'", () => {
  let testdata = {
    "A128KW": {
      alg: "A128KW",
      length: 128,
      cases: [
        {
          // 128-bit wrapping key, 128-bit key
          description: "128-bit wrappingKey, 128-bit key",
          wrappingKey: "dXXaOpNgfMK_2M7Hqt_Zpg",
          key: "QhNtPDhKPurJWgZv0o_tPw",
          encrypted_key: "Ax9r1-YeZD32hZSBb2TKo_Vvq-olSPX7"
        },
        {
          description: "128-bit wrapping key, 192-bit key",
          wrappingKey: "Z65CcLzdMegya35_lMgCdg",
          wrappingKeyLength: 128,
          key: "V-dIti-8N7ol6QTulz0BsTbPfB0MjFyH",
          encrypted_key: "ls7A4ycqIfqlUKhXlXqjjOPBzwbw3Z9bXFxCLO9saaE"
        },
        {
          description: "128-bit wrapping key, 256-bit key",
          wrappingKey: "5dBY5_HCLAFsThzJsmufjw",
          key: "f2BOm40508keGT_m8ZbB49piEafJozuIc7ZLE40YA-Q",
          encrypted_key: "YLn4rHl8VuAem1-E1lgWqYB3eGn2eZGg5twZuM11ybVNtKOEVrvW8w"
        }
      ]
    }
  };

  before(async () => {
    let all = [];
    Object.keys(testdata).forEach(alg => {
      let algset = testdata[alg].cases.map(async (tc) => {
        // decode all the things
        ["wrappingKey", "key", "encrypted_key"].forEach(k => {
          tc[k] = BASE64.decode(tc[k]);
        });

        // setup (wrapped key) cipher
        tc.cipher = AESGCM.ciphers[`A${tc.key.length * 8}GCM`];

        // convert to a key
        tc.wrappingKey = await webcrypto.subtle.importKey("raw", tc.wrappingKey, "AES-KW", true, ["wrapKey", "unwrapKey"]);
        tc.key = await webcrypto.subtle.importKey("raw", tc.key, "AES-GCM", true, ["encrypt", "decrypt"]);
      });
      all = all.concat(algset);
    });

    return Promise.all(all);
  });

  describe("ciphers", () => {
    Object.keys(testdata).forEach(alg => {
      describe(alg, () => {
        let details = testdata[alg];
        let cipher = AESKW.ciphers[alg];

        it("has expected methods", () => {
          ["configure", "generateKey", "wrapKey", "unwrapKey"].forEach(m => assert.typeOf(cipher[m], "function"));
        });
        it("configures options for 'generateKey'", () => {
          let opts;
          opts = cipher.configure("generateKey");
          assert.typeOf(opts, "object");
          assert.deepEqual(opts.wrappingAlgorithm, {
            name: "AES-KW",
            length: details.length
          });
          assert.deepEqual(opts.header, {
            alg: alg
          });
          assert.strictEqual(opts.wrappingFormat, "raw");
        });
        it("configures options for 'wrapKey'", () => {
          let opts;
          opts = cipher.configure("wrapKey");
          assert.typeOf(opts, "object");
          assert.deepEqual(opts.wrappingAlgorithm, {
            name: "AES-KW",
            length: details.length
          });
          assert.deepEqual(opts.header, {
            alg: alg
          });
          assert.strictEqual(opts.wrappingFormat, "raw");

          let orig = {};
          opts = cipher.configure("wrapKey", orig);
          assert.strictEqual(opts, orig);
          assert.typeOf(opts, "object");
          assert.deepEqual(opts.wrappingAlgorithm, {
            name: "AES-KW",
            length: details.length
          });
          assert.deepEqual(opts.header, {
            alg: alg
          });
          assert.strictEqual(opts.wrappingFormat, "raw");
        });
        it("configures options for 'unwrapKey'", () => {
          let opts;
          opts = cipher.configure("unwrapKey");
          assert.typeOf(opts, "object");
          assert.deepEqual(opts.wrappingAlgorithm, {
            name: "AES-KW",
            length: details.length
          });
          assert.deepEqual(opts.header, {
            alg: alg
          });
          assert.strictEqual(opts.wrappingFormat, "raw");

          let orig = {};
          opts = cipher.configure("unwrapKey", orig);
          assert.strictEqual(opts, orig);
          assert.typeOf(opts, "object");
          assert.deepEqual(opts.wrappingAlgorithm, {
            name: "AES-KW",
            length: details.length
          });
          assert.deepEqual(opts.header, {
            alg: alg
          });
          assert.strictEqual(opts.wrappingFormat, "raw");
        });

        it("generates a key", async () => {
          let opts;
          opts = await cipher.generateKey();
          assert(opts.wrappingKey);
        });

        for (let tc of details.cases) {
          let { description } = tc;

          it(`wraps key (${description})`, async () => {
            let opts = Object.assign({}, tc);
            let results = await cipher.wrapKey(opts);
            let expected = {
              encrypted_key: tc.encrypted_key
            };
            for (let e of Object.keys(expected)) {
              assert.deepEqual(results[e], expected[e]);
            }
          });
          it(`unwraps key (${description})`, async () => {
            let opts = Object.assign({}, tc);
            delete opts.key;

            let results = await cipher.unwrapKey(opts);
            assert.containsAllKeys(results, ["algorithm", "key"]);

            let actual, expected;
            // test (unwrapped) key equality
            actual = await webcrypto.subtle.exportKey("raw", results.key);
            expected = await webcrypto.subtle.exportKey("raw", tc.key);
            assert.deepEqual(actual, expected);
            // test (unwrapped) algorithm equality
            actual = results.algorithm;
            expected = tc.cipher.configure().algorithm;
            assert.deepEqual(actual, expected);
          });
        }
      });
    });
  });
});
