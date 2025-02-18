'use strict';

// see https://eslint.org/
// see https://github.com/typescript-eslint/typescript-eslint
// see https://typescript-eslint.io/
// see https://typescript-eslint.io/getting-started

// config based on https://www.robertcooper.me/using-eslint-and-prettier-in-a-typescript-project
// and https://typescript-eslint.io/getting-started
module.exports = {
	parser: '@typescript-eslint/parser', // Specifies the ESLint parser

	parserOptions: {
		ecmaVersion: 'latest', // Allows for the parsing of modern ECMAScript features
		// see https://typescript-eslint.io/packages/parser#project
		project: [
			'./tsconfig.json',
			'./test/tsconfig.json',
			'./scripts/tsconfig.json',
			'./geospatial/tsconfig.json',
			'./ai/tsconfig.json',
		],
	},

	extends: [
		'eslint:recommended',
		// Note:
		//   @typescript-eslint/recommended automatically disables the conflicting base rules
		//   that comes from eslint:recommended.
		//   See Extension Rules at https://typescript-eslint.io/rules/?=extension#extension-rules
		//   See https://typescript-eslint.io/linting/configs/#recommended
		//   See https://github.com/typescript-eslint/typescript-eslint/blob/main/packages/eslint-plugin/src/configs/recommended.ts
		//   TODO: Switch to @typescript-eslint/recommended-type-checked or @typescript-eslint/strict-type-checked
		'plugin:@typescript-eslint/recommended',
	],

	rules: {
		// https://eslint.org/docs/latest/rules/eqeqeq
		// Require the use of === and !==
		eqeqeq: 'error',

		// https://typescript-eslint.io/rules/no-unused-vars
		// It is set to 'error' by @typescript-eslint/recommended
		// (which also correctly disables ESLint's base no-unused-vars).
		// Let's decrease to only 'warn'.
		'@typescript-eslint/no-unused-vars': 'warn',

		// https://typescript-eslint.io/rules/strict-boolean-expressions
		'@typescript-eslint/strict-boolean-expressions': [
			'error',
			{
				// it is better to be explicit
				allowString: false,
				allowNumber: false,
				allowNullableObject: false,
			},
		],

		// https://typescript-eslint.io/rules/prefer-nullish-coalescing
		'@typescript-eslint/prefer-nullish-coalescing': 'error',

		// https://typescript-eslint.io/rules/class-methods-use-this
		// could be useful
		// 'class-methods-use-this': 'off',
		// '@typescript-eslint/class-methods-use-this': 'error',
	},

	// https://eslint.org/docs/latest/use/configure/rules#using-configuration-files-1
	overrides: [
		{
			files: ['test/**/*.ts'],
			rules: {
				'@typescript-eslint/no-unused-vars': 'off',
			},
		},
	],

	// This file is the root-level one used by the project
	// and ESLint should not search beyond this directory for config files
	root: true,
};
