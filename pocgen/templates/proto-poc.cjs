'use strict';

// Minimal prototype-pollution PoC template. Fill in the target call and assert
// pollution on a fresh object or the intended target object.

const payload = JSON.parse('{"__proto__":{"polluted":"JSFLOW_POC_SUCCESS"}}');

function main() {
  // const target = require('./index.js');
  // target(payload);
  if (({}).polluted === 'JSFLOW_POC_SUCCESS') {
    console.log('PASS');
    return;
  }
  console.log('FAIL');
  process.exitCode = 1;
}

main();

