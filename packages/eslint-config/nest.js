import base from "./index.js";

export default [
  ...base,
  {
    files: ["src/**/*.ts"],
    rules: {
      "@typescript-eslint/no-extraneous-class": "off",
      "@typescript-eslint/parameter-properties": "off",
      "@typescript-eslint/no-empty-function": ["error", { allow: ["constructors"] }]
    }
  }
];
