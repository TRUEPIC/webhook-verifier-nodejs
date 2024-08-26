import js from '@eslint/js'
import prettier from 'eslint-config-prettier'
import node from 'eslint-plugin-n'
import globals from 'globals'

export default [
  {
    languageOptions: {
      globals: { ...globals.node },
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
