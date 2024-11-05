const js = require('@eslint/js')
const prettier = require('eslint-config-prettier')
const node = require('eslint-plugin-n')
const globals = require('globals')

module.exports = [
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
  {
    rules: {
      'n/no-unsupported-features/node-builtins': [
        'error',
        {
          ignores: ['test', 'test.describe', 'test.it'],
        },
      ],
    },
  },
  prettier,
]
