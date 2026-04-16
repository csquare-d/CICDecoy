import js from "@eslint/js";
import reactPlugin from "eslint-plugin-react";
import reactHooksPlugin from "eslint-plugin-react-hooks";
import globals from "globals";

export default [
  // Recommended JS rules for all files
  js.configs.recommended,

  // Main config for source files
  {
    files: ["src/**/*.{js,jsx}"],
    plugins: {
      react: reactPlugin,
      "react-hooks": reactHooksPlugin,
    },
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      globals: {
        ...globals.browser,
      },
      parserOptions: {
        ecmaFeatures: { jsx: true },
      },
    },
    settings: {
      react: { version: "18" },
    },
    rules: {
      // React rules
      "react/jsx-uses-react": "warn",
      "react/jsx-uses-vars": "warn",
      "react/jsx-no-duplicate-props": "error",
      "react/jsx-no-undef": "error",
      "react/jsx-key": "error",
      "react/no-children-prop": "error",
      "react/no-danger-with-children": "error",
      "react/no-direct-mutation-state": "error",
      "react/no-unescaped-entities": "warn",
      "react/prop-types": "off", // not using PropTypes in this codebase
      "react/react-in-jsx-scope": "off", // React 18 JSX transform

      // React Hooks rules
      "react-hooks/rules-of-hooks": "error",
      "react-hooks/exhaustive-deps": "warn",

      // Possible errors
      "no-console": "off", // dashboard uses console.warn for diagnostics
      "no-unused-vars": ["warn", { argsIgnorePattern: "^_", varsIgnorePattern: "^_" }],
      "no-undef": "error",

      // Stylistic (warn only)
      "no-var": "warn",
      "prefer-const": "warn",
      "eqeqeq": ["warn", "smart"],
    },
  },

  // Relaxed config for test files
  {
    files: ["src/**/*.test.{js,jsx}"],
    languageOptions: {
      globals: {
        ...globals.browser,
        // Vitest globals (configured with globals: true in vite.config.js)
        describe: "readonly",
        it: "readonly",
        test: "readonly",
        expect: "readonly",
        vi: "readonly",
        beforeEach: "readonly",
        afterEach: "readonly",
        beforeAll: "readonly",
        afterAll: "readonly",
      },
    },
    rules: {
      "no-unused-vars": "off",
    },
  },

  // Ignore build output
  {
    ignores: ["static/", "dist/", "node_modules/"],
  },
];
