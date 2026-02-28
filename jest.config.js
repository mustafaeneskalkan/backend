/** @type {import('jest').Config} */
export default {
  testEnvironment: "node",
  roots: ["<rootDir>/test"],

  // Treat TS as ESM (project itself is ESM: "type": "module")
  preset: "ts-jest/presets/default-esm",
  extensionsToTreatAsEsm: [".ts"],

  setupFiles: ["<rootDir>/test/jest.setup.ts"],

  transform: {
    "^.+\\.tsx?$": [
      "ts-jest",
      {
        useESM: true,
        tsconfig: "<rootDir>/tsconfig.jest.json",
      },
    ],
  },

  // Allow TS sources to be imported using .js extensions (NodeNext style)
  moduleNameMapper: {
    "^(\\.{1,2}/.*)\\.js$": "$1",
  },
};
