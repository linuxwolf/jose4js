/*!
 *
 */

const assert = require("chai").assert;

const webcrypto = require("../../lib/util/webcrypto");

describe("webcrypto", () => {
  it("tests existence", () => {
    assert.exists(webcrypto);
    assert.typeOf(webcrypto.getRandomValues, "function");
    assert.exists(webcrypto.subtle);
  });
});
