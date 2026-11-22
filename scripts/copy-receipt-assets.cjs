const { cpSync } = require('node:fs');
const { resolve } = require('node:path');

cpSync(
    resolve(__dirname, '../src/modules/entries/assets'),
    resolve(__dirname, '../dist/modules/entries/assets'),
    { recursive: true },
);

cpSync(
    resolve(__dirname, '../src/modules/invoicing/assets'),
    resolve(__dirname, '../dist/modules/invoicing/assets'),
    { recursive: true },
);
