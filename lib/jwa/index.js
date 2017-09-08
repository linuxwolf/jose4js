/*!
 *
 */

let ciphers = {};
let managers = {};

["dir", "aes-gcm", "aes-kw"].forEach(name => {
  let m = require(`./${name}`);
  managers[m.name] = m;
  Object.keys(m.ciphers).forEach(c => ciphers[c] = m.ciphers[c]);
});

exports.findByKey = (key, mode) => {
  let mgr = managers[key.algorithm.name];
  if (!mgr) { return null; }
  if (!mgr.map) { return null; }
  return ciphers[mgr.map(key, mode)];
};

exports.cipher = alg => {
  return ciphers[alg];
};
