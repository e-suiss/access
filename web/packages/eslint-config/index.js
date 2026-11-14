// OP-83, OP-159 m.36
import js from "@eslint/js";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";
import tseslint from "typescript-eslint";

/** The lint profile of an Access web package rooted at `tsconfigRootDir`; `ignores` adds paths. */
export function config(tsconfigRootDir, ignores = []) {
  return tseslint.config(
    {
      ignores: [
        "node_modules/**",
        "dist/**",
        "test-results/**",
        "playwright-report/**",
        ...ignores,
      ],
    },
    js.configs.recommended,
    ...tseslint.configs.strictTypeChecked,
    ...tseslint.configs.stylisticTypeChecked,
    {
      languageOptions: {
        parserOptions: {
          projectService: true,
          tsconfigRootDir,
        },
      },
    },
    {
      files: ["**/*.js"],
      extends: [tseslint.configs.disableTypeChecked],
      languageOptions: { globals: globals.node },
    },
    {
      files: ["**/*.{ts,tsx}"],
      plugins: { "react-hooks": reactHooks },
      rules: {
        ...reactHooks.configs.recommended.rules,
        // TN-131
        "no-restricted-syntax": [
          "error",
          {
            selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
            message: "Render text nodes only (TN-131).",
          },
          {
            selector: "MemberExpression[property.name=/^(innerHTML|outerHTML)$/]",
            message: "Render text nodes only (TN-131).",
          },
        ],
      },
      languageOptions: { globals: globals.browser },
    },
  );
}
