module.exports = {
  extends: ["eslint:recommended", "plugin:@typescript-eslint/recommended"],
  root: true,
  parser: "@typescript-eslint/parser",
  parserOptions: {
    project: "./tsconfig.json",
    tsconfigRootDir: __dirname
  },
  plugins: ["@typescript-eslint"]
};
