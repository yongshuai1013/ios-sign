'use strict';

const createApi = require('./api.cjs');
const wasmBundle = require('../dist/zsign-wasm.min.js');

module.exports = createApi(wasmBundle);
