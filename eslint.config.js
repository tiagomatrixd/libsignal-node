// ESLint 9.x Flat Configuration (CommonJS)
module.exports = [
    {
        files: ["**/*.js"],
        languageOptions: {
            ecmaVersion: 2022,
            sourceType: "commonjs",
            globals: {
                Buffer: "readonly",
                process: "readonly",
                console: "readonly",
                require: "readonly",
                module: "readonly",
                exports: "readonly",
                __dirname: "readonly",
                __filename: "readonly",
                global: "readonly",
                setTimeout: "readonly",
                clearTimeout: "readonly",
                setInterval: "readonly",
                clearInterval: "readonly"
            }
        },
        rules: {
            "no-unused-vars": "warn",
            "no-console": "off",
            "no-undef": "error",
            "semi": ["error", "always"],
            "quotes": ["error", "single", { "allowTemplateLiterals": true }]
        }
    }
];
