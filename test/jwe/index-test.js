/*!
 *
 */

const assert = require("chai").assert;

const JWE = require("../../lib/jwe/index");

describe("index", () => {
  it("exports all symbols", () => {
    let expected = {
      "encrypt": "function",
      "decrypt": "function"
    };

    Object.keys(JWE).forEach(m => {
      if (!(m in expected)) {
        assert(false, `unexpected symbol ${m}`);
      }
      assert.typeOf(JWE[m], expected[m]);
    });
  });
});
