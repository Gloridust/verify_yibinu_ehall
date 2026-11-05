#!/usr/bin/env node
// 构建原生模块并复制为 ./yibinu_auth.node
// 用法：node scripts/build.js [--debug] [--vendored-openssl]
'use strict';
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..', '..', '..');
const debug = process.argv.includes('--debug');
const args = ['build', '-p', 'yibinu-auth-node', '--manifest-path', path.join(root, 'Cargo.toml')];
if (!debug) args.push('--release');
if (process.argv.includes('--vendored-openssl')) args.push('--features', 'vendored-openssl');
execFileSync('cargo', args, { stdio: 'inherit' });

const name = {
  win32: 'yibinu_auth_node.dll',
  darwin: 'libyibinu_auth_node.dylib',
}[process.platform] || 'libyibinu_auth_node.so';
const src = path.join(root, 'target', debug ? 'debug' : 'release', name);
const dest = path.join(__dirname, '..', 'yibinu_auth.node');
fs.copyFileSync(src, dest);
console.log(`OK: ${dest}`);
