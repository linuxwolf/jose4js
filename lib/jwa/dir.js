/*!
 *
 */

const UTILS = require("./utils");
const KEYS = require("../util/keys");

function _setup() {
  let cfg = {};
  cfg.configure = (mode, opts) => {
    opts = opts || {};

    let header = {
      alg: "dir"
    };
    opts.header = Object.assign(opts.header || {}, header);

    return opts;
  };

  cfg = UTILS.defineOperation(cfg, "deriveKey", async (params) => {
    let {
      header,
      key
    } = params;
    // try to resovle a key
    key = await KEYS.asKey(key);
    if (!key) {
      throw new Error("missing content encryption key");
    }
    if ("secret" !== key.type) {
      throw new Error("invalid content encryption key");
    }

    return Object.assign(params, {
      header,
      key
    });
  });

  return cfg;
}

let ciphers = {
  "dir": _setup()
};

Object.assign(exports, {
  name: "dir",
  ciphers
});
