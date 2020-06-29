module.exports = {
  tabWidth: 4,
  printWidth: 120,
  proseWrap: 'preserve',
  semi: false,
  trailingComma: 'es5',
  singleQuote: true,
  overrides: [
    {
      files: '{*.js?(on),*.md,.prettierrc,.babelrc}',
      options: {
        tabWidth: 2,
      },
    },
  ],
}
