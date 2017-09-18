/*!
 *
 */

const webcrypto = require("../util/webcrypto");
const BUFFERS = require("../util/buffers"),
      KEYS = require("../util/keys"),
      UTILS = require("./utils");

function _setup(alg) {
  let parts = /^A(128|192|256)KW$/g.exec(alg);
  let name = "AES-KW",
      length = parseInt(parts[1]),
      modes = ["wrapKey", "unwrapKey"];

  let cfg = {};
  cfg.configure = (mode, opts) => {
    opts = opts || {};

    opts.wrappingFormat = "raw";
    let algorithm = {
      name,
      length
    };
    opts.wrappingAlgorithm = Object.assign(opts.wrappingAlgorithm || {}, algorithm);

    let header = {
      alg: alg
    };
    opts.header = Object.assign(opts.header || {}, header);

    return opts;
  };

  cfg = UTILS.defineOperation(cfg, "generateKey", async (params) => {
    let {
      wrappingAlgorithm,
      extractable = true,
      usages = modes
    } = params;

    let wrappingKey = await webcrypto.subtle.generateKey(wrappingAlgorithm, extractable, usages);

    return { wrappingKey };
  });
  cfg = UTILS.defineOperation(cfg, "wrapKey", async (params) => {
    let {
      header,
      wrappingFormat,
      wrappingAlgorithm,
      wrappingKey,
      key
    } = params;
    wrappingKey = await KEYS.asKey(wrappingKey);
    key = await KEYS.asKey(key);

    let encrypted_key = await webcrypto.subtle.wrapKey(wrappingFormat,
                                                       key,
                                                       wrappingKey,
                                                       wrappingAlgorithm);
    encrypted_key = BUFFERS.asBuffer(encrypted_key);

    return {
      header,
      encrypted_key
    };
  });
  cfg = UTILS.defineOperation(cfg, "unwrapKey", async (params) => {
    let {
      wrappingFormat,
      wrappingAlgorithm,
      wrappingKey,
      encrypted_key,
      cipher
    } = params;
    wrappingKey = await KEYS.asKey(wrappingKey);

    let {
      algorithm,
      extractable = true,
      usages = ["encrypt", "decrypt"]
    } = cipher.configure();

    let key = await webcrypto.subtle.unwrapKey(wrappingFormat,
                                               encrypted_key,
                                               wrappingKey,
                                               wrappingAlgorithm,
                                               algorithm,
                                               extractable,
                                               usages);
    return { algorithm, key };
  });

  return cfg;
}

let ciphers = {};
["A128KW", "A192KW", "A256KW"].forEach(a => (ciphers[a] = _setup(a)));

const USAGES = ["wrapKey", "unwrapKey"];
function map(key, mode) {
  return supports(key, mode)[0] || "";
}

function supports(key, modes) {
  let { name, length = 128 } = key.algorithm;
  if ("AES-KW" === name) {
    if ("string" === typeof modes) {
      modes = [modes];
    } else if (!modes) {
      modes = USAGES;
    }
    modes = key.usages.filter(u => (modes.indexOf(u) !== -1));

    let algs = new Set();
    modes.forEach(m => {
      let a;
      switch (m) {
        case "wrapKey":
        case "unwrapKey":
          a = `A${length}KW`;
          break;
      }
      if (a) {
        algs.add(a);
      }
    });
    algs = [...algs];

    return algs;
  }
  return [];
}

Object.assign(exports, {
  name: "AES-KW",
  ciphers,
  map,
  supports
});
