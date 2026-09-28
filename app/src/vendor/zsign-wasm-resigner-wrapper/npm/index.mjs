import JSZip from 'jszip';
const MODULE_URL = new URL(import.meta.url);
const IS_NODE = MODULE_URL.protocol === 'file:';
const WASM_BUNDLE_URL = new URL('../dist/zsign-wasm.min.js', MODULE_URL);
const WASM_BUNDLE_SPECIFIER = '../dist/zsign-wasm.min.js';

let wasmBundlePromise = null;

function toUint8Array(value, name) {
  if (value instanceof Uint8Array) {
    return value;
  }
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }
  throw new TypeError(`${name} must be Uint8Array, Buffer, or ArrayBuffer.`);
}

function normalizePath(p) {
  return String(p || '').replace(/\\/g, '/').replace(/^\/+/, '');
}

function resolveBundleExports(input) {
  if (input && typeof input === 'object' && input.default) {
    const nested = resolveBundleExports(input.default);
    if (nested) {
      return nested;
    }
  }

  if (!input || typeof input !== 'object') {
    return null;
  }

  if (typeof input.ZsignWasmClient === 'function') {
    return input;
  }

  return null;
}

async function loadNodeBundle() {
  const [{ createRequire }, { fileURLToPath }] = await Promise.all([
    import('node:module'),
    import('node:url')
  ]);
  const require = createRequire(import.meta.url);
  return require(fileURLToPath(WASM_BUNDLE_URL));
}

async function loadBrowserBundle() {
  const imported = await import(WASM_BUNDLE_SPECIFIER);
  const resolved = resolveBundleExports(imported);
  if (!resolved) {
    throw new Error('Invalid wasm bundle exports.');
  }
  return resolved;
}

async function getWasmBundle() {
  if (!wasmBundlePromise) {
    wasmBundlePromise = (async () => {
      const loaded = IS_NODE ? await loadNodeBundle() : await loadBrowserBundle();
      const resolved = resolveBundleExports(loaded);
      if (!resolved) {
        throw new Error('Invalid wasm bundle exports.');
      }
      return resolved;
    })();
  }

  return wasmBundlePromise;
}

export async function createZsignModule(opts = {}) {
  const bundle = await getWasmBundle();
  const factory = bundle.createZsignModule || bundle.createEmbeddedZsignModule;
  if (typeof factory !== 'function') {
    throw new Error('Cannot resolve wasm module factory.');
  }
  return factory(opts);
}

export async function createEmbeddedZsignModule(opts = {}) {
  const bundle = await getWasmBundle();
  const factory = bundle.createEmbeddedZsignModule || bundle.createZsignModule;
  if (typeof factory !== 'function') {
    throw new Error('Cannot resolve embedded wasm module factory.');
  }
  return factory(opts);
}

export class ZsignWasmClient {
  static async create(options = {}) {
    const bundle = await getWasmBundle();
    const ClientClass = bundle.ZsignWasmClient;
    const client = await ClientClass.create(options);
    return new ZsignWasmClient(client);
  }

  constructor(client) {
    if (!client) {
      throw new Error('client is required.');
    }
    this.client = client;
    this.mod = client.mod;
  }

  version() {
    return this.client.version();
  }

  setLogLevel(level) {
    return this.client.setLogLevel(level);
  }

  signMachO(inputMachO, options = {}) {
    return this.client.signMacho(inputMachO, options);
  }

  signBundle(inputFolder, options = {}) {
    return this.client.signBundle(inputFolder, options);
  }

  signMachoToFile(inputPath, outputPath, options = {}) {
    if (typeof this.client.signMachoToFile !== 'function') {
      throw new Error('signMachoToFile is not available in this runtime.');
    }
    return this.client.signMachoToFile(inputPath, outputPath, options);
  }
}

export class ZsignWasmResigner {
  static async create(options = {}) {
    let moduleFactory = options.moduleFactory;
    if (!moduleFactory) {
      const bundle = await getWasmBundle();
      moduleFactory = bundle.createEmbeddedZsignModule || bundle.createZsignModule;
    }
    if (typeof moduleFactory !== 'function') {
      throw new Error('Cannot resolve wasm module factory.');
    }

    const client = await ZsignWasmClient.create({
      moduleFactory,
      moduleOptions: options.moduleOptions || {}
    });
    return new ZsignWasmResigner(client);
  }

  constructor(client) {
    this.client = client;
    this.mod = client.mod;
    this.fs = this.mod.FS;
    if (!this.fs) {
      throw new Error('Emscripten FS is not available.');
    }
  }

  version() {
    return this.client.version();
  }

  setLogLevel(level) {
    return this.client.setLogLevel(level);
  }

  signMachO(inputMachO, options = {}) {
    return this.client.signMachO(inputMachO, options);
  }

  async signIpa(inputIpa, options = {}) {
    const ipaBytes = toUint8Array(inputIpa, 'inputIpa');
    const inputZip = await JSZip.loadAsync(ipaBytes);
    const workspace = this._newWorkspacePath();
    const inputRoot = `${workspace}/input`;
    const assetRoot = `${workspace}/assets`;

    this.fs.mkdirTree(inputRoot);
    this.fs.mkdirTree(assetRoot);

    try {
      const names = Object.keys(inputZip.files);
      for (const name of names) {
        const entry = inputZip.files[name];
        const cleanName = normalizePath(name);
        if (!cleanName) {
          continue;
        }
        const outPath = `${inputRoot}/${cleanName}`;
        if (entry.dir) {
          this.fs.mkdirTree(outPath);
        } else {
          const data = await entry.async('uint8array');
          this._writeFile(outPath, data);
        }
      }

      const certFile = this._writeOptionalAsset(assetRoot, 'cert.bin', options.cert);
      const pkeyFile = this._writeOptionalAsset(assetRoot, 'pkey.bin', options.pkey);
      const provFile = this._writeOptionalAsset(assetRoot, 'prov.mobileprovision', options.prov);
      const entitlementsFile = this._writeOptionalAsset(assetRoot, 'entitlements.plist', options.entitlements);

      this.client.signBundle(inputRoot, {
        certFile,
        pkeyFile,
        provFile,
        password: typeof options.password === 'string' ? options.password : '',
        entitlementsFile,
        bundleId: typeof options.bundleId === 'string' ? options.bundleId : '',
        bundleVersion: typeof options.bundleVersion === 'string' ? options.bundleVersion : '',
        displayName: typeof options.displayName === 'string' ? options.displayName : '',
        adhoc: !!options.adhoc,
        sha256Only: !!options.sha256Only,
        forceSign: options.forceSign !== undefined ? !!options.forceSign : true,
        weakInject: !!options.weakInject,
        enableCache: !!options.enableCache
      });

      const outZip = new JSZip();
      this._walkFiles(inputRoot, (absPath) => {
        const relPath = absPath.slice(inputRoot.length + 1);
        const fileData = this.fs.readFile(absPath, { encoding: 'binary' });
        outZip.file(relPath, fileData);
      });

      return outZip.generateAsync({
        type: 'uint8array',
        compression: 'DEFLATE',
        compressionOptions: {
          level: Number.isInteger(options.zipLevel) ? options.zipLevel : 9
        }
      });
    } finally {
      this._rmrf(workspace);
    }
  }

  _writeOptionalAsset(assetRoot, filename, data) {
    if (data == null) {
      return '';
    }
    const bytes = toUint8Array(data, filename);
    const outPath = `${assetRoot}/${filename}`;
    this._writeFile(outPath, bytes);
    return outPath;
  }

  _writeFile(outPath, data) {
    const idx = outPath.lastIndexOf('/');
    if (idx > 0) {
      this.fs.mkdirTree(outPath.slice(0, idx));
    }
    this.fs.writeFile(outPath, data, { canOwn: true });
  }

  _walkFiles(rootPath, onFile) {
    const entries = this.fs.readdir(rootPath);
    for (const name of entries) {
      if (name === '.' || name === '..') {
        continue;
      }
      const fullPath = `${rootPath}/${name}`;
      const st = this.fs.stat(fullPath);
      if (this.fs.isDir(st.mode)) {
        this._walkFiles(fullPath, onFile);
      } else if (this.fs.isFile(st.mode)) {
        onFile(fullPath);
      }
    }
  }

  _rmrf(pathname) {
    const info = this.fs.analyzePath(pathname);
    if (!info.exists) {
      return;
    }

    const st = this.fs.stat(pathname);
    if (this.fs.isDir(st.mode)) {
      const entries = this.fs.readdir(pathname);
      for (const name of entries) {
        if (name === '.' || name === '..') {
          continue;
        }
        this._rmrf(`${pathname}/${name}`);
      }
      this.fs.rmdir(pathname);
    } else {
      this.fs.unlink(pathname);
    }
  }

  _newWorkspacePath() {
    const suffix = `${Date.now()}_${Math.floor(Math.random() * 1e9)}`;
    const workspace = `/zsign_ws_${suffix}`;
    this.fs.mkdirTree(workspace);
    return workspace;
  }
}

export function createResigner(options = {}) {
  return ZsignWasmResigner.create(options);
}

const api = {
  ZsignWasmResigner,
  ZsignWasmClient,
  createZsignModule,
  createEmbeddedZsignModule,
  createResigner
};

export default api;
