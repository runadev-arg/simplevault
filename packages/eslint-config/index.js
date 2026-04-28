import js from "@eslint/js";
import tseslint from "typescript-eslint";
import importPlugin from "eslint-plugin-import";
import prettier from "eslint-config-prettier";

export default tseslint.config(
  js.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,
  {
    languageOptions: {
      parserOptions: { projectService: true }
    },
    plugins: { import: importPlugin },
    rules: {
      "no-console": ["error", { allow: ["warn", "error"] }],
      "no-restricted-syntax": [
        "error",
        { selector: "TSEnumDeclaration", message: "Use string union types instead of enums." }
      ],
      "@typescript-eslint/no-floating-promises": "error",
      "@typescript-eslint/no-misused-promises": "error",
      "@typescript-eslint/consistent-type-imports": "error",
      "import/order": ["error", { "newlines-between": "always", alphabetize: { order: "asc" } }]
    }
  },
  prettier,
  { ignores: ["dist/**", ".next/**", ".turbo/**", "node_modules/**", "*.config.{js,mjs,ts}"] }
);
