# [2.5.0](https://github.com/ivaisoft/secrets-webauthn-mcp/compare/v2.4.0...v2.5.0) (2026-08-10)


### Features

* optional Reuse Window covering one exact request, bounded by time and runs ([#13](https://github.com/ivaisoft/secrets-webauthn-mcp/issues/13)) ([52c0a88](https://github.com/ivaisoft/secrets-webauthn-mcp/commit/52c0a88af8255504e2a6c291897fb4905ebda808))

# [2.4.0](https://github.com/ivaisoft/secrets-webauthn-mcp/compare/v2.3.1...v2.4.0) (2026-08-10)


### Features

* enumerate SSM Parameter Store under a configured path prefix ([#12](https://github.com/ivaisoft/secrets-webauthn-mcp/issues/12)) ([be785da](https://github.com/ivaisoft/secrets-webauthn-mcp/commit/be785da9d7249de48ca63a1d1808052d50ca846a))

## [2.3.1](https://github.com/ivaisoft/secrets-webauthn-mcp/compare/v2.3.0...v2.3.1) (2026-08-10)


### Bug Fixes

* explain an empty list_secrets instead of returning a bare [] ([#11](https://github.com/ivaisoft/secrets-webauthn-mcp/issues/11)) ([81cf9a9](https://github.com/ivaisoft/secrets-webauthn-mcp/commit/81cf9a9ca44f3dc64f24f0a2d6014bd4b5ce5ef3))

# [2.3.0](https://github.com/ivaisoft/secrets-webauthn-mcp/compare/v2.2.0...v2.3.0) (2026-08-10)


### Features

* address secrets by Store — AWS SSM Parameter Store and Secrets Manager ([#7](https://github.com/ivaisoft/secrets-webauthn-mcp/issues/7)) ([dc25b8a](https://github.com/ivaisoft/secrets-webauthn-mcp/commit/dc25b8a3f21b481544b992e3f5c656d081491c1f)), closes [#subkey](https://github.com/ivaisoft/secrets-webauthn-mcp/issues/subkey) [#subkey](https://github.com/ivaisoft/secrets-webauthn-mcp/issues/subkey)

# [2.2.0](https://github.com/ivaisoft/bws-webauthn-mcp/compare/v2.1.2...v2.2.0) (2026-07-31)


### Features

* redesign /approve and /register with a real design system ([79f5c42](https://github.com/ivaisoft/bws-webauthn-mcp/commit/79f5c427163f2eefc45d5604db45c8651770ef29))

## [2.1.2](https://github.com/ivaisoft/bws-webauthn-mcp/compare/v2.1.1...v2.1.2) (2026-07-31)


### Bug Fixes

* [secure] was published without the executable bit, breaking npx ([c9b25fc](https://github.com/ivaisoft/bws-webauthn-mcp/commit/c9b25fccd07c6d9fd29337a3dc103b5f787f6cf1))

## [2.1.1](https://github.com/ivaisoft/bws-webauthn-mcp/compare/v2.1.0...v2.1.1) (2026-07-31)


### Bug Fixes

* reject env_overrides keys not in secret_ids, before Approval ([4539b30](https://github.com/ivaisoft/bws-webauthn-mcp/commit/4539b309d068a1427b78e04f9f8da96b701852b6))
