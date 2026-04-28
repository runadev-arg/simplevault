import base from "./index.js";

export default [
  ...base,
  {
    files: ["src/**/*.{ts,tsx}"],
    rules: {
      // Next.js specific tightening
      "no-restricted-imports": ["error", {
        patterns: [{
          group: ["**/server/*", "@simplevault/db", "@simplevault/db/*"],
          message: "Server-only modules cannot be imported from web client code. Use API routes."
        }]
      }]
    }
  }
];
