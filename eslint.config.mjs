import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import globals from 'globals';
export default tseslint.config(
 {ignores:['**/dist/**','**/node_modules/**','legacy/**','**/.angular/**']},
 js.configs.recommended,
 ...tseslint.configs.recommended,
 {files:['**/*.ts'],languageOptions:{globals:{...globals.node,...globals.browser}},rules:{'@typescript-eslint/no-unused-vars':['error',{argsIgnorePattern:'^_',varsIgnorePattern:'^_'}]}}
);
