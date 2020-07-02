/* eslint-disable @typescript-eslint/no-empty-function */
// __test-utils__/custom-jest-environment.js
// Stolen from: https://github.com/ipfs/jest-environment-aegir/blob/master/src/index.js
// Overcomes error from jest internals.. this thing: https://github.com/facebook/jest/issues/6248
'use strict'

// eslint-disable-next-line @typescript-eslint/no-var-requires
const NodeEnvironment = require('jest-environment-node')

class MyEnvironment extends NodeEnvironment {
  constructor(config) {
    super(
      Object.assign({}, config, {
        globals: Object.assign({}, config.globals, {
          Uint32Array: Uint32Array,
          Uint16Array: Uint16Array,
          Uint8Array: Uint8Array,
          ArrayBuffer: ArrayBuffer,
        }),
      })
    )
  }

  async setup() {}

  async teardown() {}
}

module.exports = MyEnvironment
