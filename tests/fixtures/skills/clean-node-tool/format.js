import { readFileSync, writeFileSync } from 'node:fs';

const target = process.argv[2];
if (!target) {
  console.error('usage: node format.js <path>');
  process.exit(1);
}

const data = JSON.parse(readFileSync(target, 'utf8'));
writeFileSync(target, JSON.stringify(data, null, 2) + '\n');
console.log(`formatted ${target}`);
