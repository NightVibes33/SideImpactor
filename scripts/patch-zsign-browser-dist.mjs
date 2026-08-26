import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const runtimePath = resolve('wasm/zsign-wasm/dist/runtime.js');
const original = await readFile(runtimePath, 'utf8');

const oldBlock = `const MODULE_URL = new URL(import.meta.url);\nconst WASM_BUNDLE_URL = new URL("../binary/zsign-wasm.min.js", MODULE_URL);\nconst IS_NODE = MODULE_URL.protocol === "file:";`;
const newBlock = `const MODULE_URL = new URL(import.meta.url);\nconst IS_NODE = MODULE_URL.protocol === "file:";\nconst WASM_BUNDLE_URL = IS_NODE\n  ? new URL("../binary/zsign-wasm.min.js", MODULE_URL)\n  : new URL("/assets/zsign-wasm.min.js", globalThis.location?.href || MODULE_URL.href);`;

if (original.includes(newBlock)) {
  console.log('zsign browser runtime already patched');
  process.exit(0);
}

if (!original.includes(oldBlock)) {
  throw new Error('Unable to locate the pinned zsign runtime URL block');
}

await writeFile(runtimePath, original.replace(oldBlock, newBlock));
console.log('patched zsign browser runtime asset URL');
