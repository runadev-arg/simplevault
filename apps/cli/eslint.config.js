import config from "@simplevault/eslint-config";

export default [
  ...config,
  {
    ignores: ["dist/**", "node_modules/**", ".tsbuildinfo"],
  },
];
