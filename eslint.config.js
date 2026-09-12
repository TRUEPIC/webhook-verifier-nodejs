const js = require('@eslint/js')
const { defineConfig } = require('eslint/config')
const prettier = require('eslint-config-prettier')
const node = require('eslint-plugin-n')
const globals = require('globals')

module.exports = defineConfig([
  {
    languageOptions: {
      globals: { ...globals.node },
      sourceType: 'commonjs',
    },
  },
  {
    ignores: ['docs'],
  },
  js.configs.recommended,
  node.configs['flat/recommended'],
  prettier,
])
