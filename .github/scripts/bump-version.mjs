import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const version = process.argv[2];

if (!version || !/^\d+\.\d+\.\d+/.test(version)) {
  console.error('Usage: node bump-version.mjs <version>');
  console.error('Example: node bump-version.mjs 1.0.0');
  process.exit(1);
}

function updatePackageJson(filePath) {
  const content = JSON.parse(readFileSync(filePath, 'utf-8'));
  content.version = version;
  writeFileSync(filePath, JSON.stringify(content, null, 2) + '\n');
  console.log(`Updated ${filePath} to ${version}`);
}

updatePackageJson('package.json');

const packagesDir = 'packages';
for (const dir of readdirSync(packagesDir)) {
  const pkgPath = join(packagesDir, dir, 'package.json');
  try {
    updatePackageJson(pkgPath);
  } catch {
    continue;
  }
}

console.log(`All packages bumped to ${version}`);
