// No-op stand-in for the `server-only` package. The real one throws outside the react-server
// condition, which would break every Vitest run that imports server-only modules.
export {};
