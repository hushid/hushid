# Changelog

## [0.1.6](https://github.com/hushid/hushid/compare/hushid-v0.1.5...hushid-v0.1.6) (2026-11-19)


### Features

* issue a token without storing the original ([#261](https://github.com/hushid/hushid/issues/261)) ([ff62a68](https://github.com/hushid/hushid/commit/ff62a68eadb926d504f8189f657cf9d2c8857915))


### Bug Fixes

* find proxy binaries on Windows and bump patch deps ([#262](https://github.com/hushid/hushid/issues/262)) ([09d2895](https://github.com/hushid/hushid/commit/09d2895a4867d82f9a999f9078a863f876037d20))
* keep a secret mark in a chat reply ([#263](https://github.com/hushid/hushid/issues/263)) ([5559640](https://github.com/hushid/hushid/commit/5559640d91fd4e4fe01382e85040cfc71b594e64))
* keep scanning tool names after a cfg(test) helper ([#258](https://github.com/hushid/hushid/issues/258)) ([4b58958](https://github.com/hushid/hushid/commit/4b5895834321e9358089ba50934f31d0b71ce878)), closes [#256](https://github.com/hushid/hushid/issues/256)
* keep the upstream content type on a chat reply ([#265](https://github.com/hushid/hushid/issues/265)) ([297f5cd](https://github.com/hushid/hushid/commit/297f5cddd8bbe2d58bb45f17b513dd394aa464c4))
* keep the upstream status reason on a chat reply ([#266](https://github.com/hushid/hushid/issues/266)) ([7fd7f2f](https://github.com/hushid/hushid/commit/7fd7f2f3cbe8144105d344fa7cf7b519e2b0469c))
* reject a sealed message count that cannot fit ([#267](https://github.com/hushid/hushid/issues/267)) ([dee2210](https://github.com/hushid/hushid/commit/dee221010d5c0506bca4bab6b2a06fdeeb1cfebd))
* restore an MCP sentence that includes a secret mark ([#264](https://github.com/hushid/hushid/issues/264)) ([291570f](https://github.com/hushid/hushid/commit/291570f1009237b20fa4d39a188617a00acfb52a))

## [0.1.5](https://github.com/hushid/hushid/compare/hushid-v0.1.4...hushid-v0.1.5) (2026-11-18)


### Features

* add search terms for the library ([#251](https://github.com/hushid/hushid/issues/251)) ([a682ccf](https://github.com/hushid/hushid/commit/a682ccfb5020912f7c5081d0f90db9a8f2f8e99e))

## [0.1.4](https://github.com/hushid/hushid/compare/hushid-v0.1.3...hushid-v0.1.4) (2026-11-18)


### Bug Fixes

* decode a chunked chat request and answer a bad one ([#226](https://github.com/hushid/hushid/issues/226)) ([11dd696](https://github.com/hushid/hushid/commit/11dd696211f2aae5214875b7981e44571dffd02f)), closes [#225](https://github.com/hushid/hushid/issues/225)
* keep a diff plus out of a domestic phone ([#235](https://github.com/hushid/hushid/issues/235)) ([3af70dd](https://github.com/hushid/hushid/commit/3af70ddc2d64e2371207c8d8ad3ab393e74df94c))
* keep a stored address token on a later shield ([#231](https://github.com/hushid/hushid/issues/231)) ([1cb058f](https://github.com/hushid/hushid/commit/1cb058f65767cd65c9e00b8f5249a29383a24ed4))
* name a bad authorization value and a bad MCP frame ([#229](https://github.com/hushid/hushid/issues/229)) ([bcb01a2](https://github.com/hushid/hushid/commit/bcb01a239bfe5ccbf5b898689585c5f984c4144a))
* name a header or length failure and a broken MCP text escape ([#228](https://github.com/hushid/hushid/issues/228)) ([c63b9bc](https://github.com/hushid/hushid/commit/c63b9bc7093ab46c2e6e2e4d6092c0f1ca32f4ec))
* refuse a shell that hides an identifier token in hex ([#234](https://github.com/hushid/hushid/issues/234)) ([3a1da78](https://github.com/hushid/hushid/commit/3a1da7828a9be4d97aae9def3ae8fb0556935ad9))
* reuse the earliest token when an address was stored twice ([#232](https://github.com/hushid/hushid/issues/232)) ([cb1a0fe](https://github.com/hushid/hushid/commit/cb1a0fe51ebf5bc7d9b4c2c616db8a50f480796c))

## [0.1.3](https://github.com/hushid/hushid/compare/hushid-v0.1.2...hushid-v0.1.3) (2026-11-16)


### Bug Fixes

* keep a chat body intact through the proxy and the vault ([#220](https://github.com/hushid/hushid/issues/220)) ([ebf6d0a](https://github.com/hushid/hushid/commit/ebf6d0a47b7565d267b45489fa594103d5739a22))
* report a broken MCP string instead of dropping the call ([#224](https://github.com/hushid/hushid/issues/224)) ([beb1bf9](https://github.com/hushid/hushid/commit/beb1bf92ba5f773e1bb089b5f60879f7b7a80f4f))

## [0.1.2](https://github.com/hushid/hushid/compare/hushid-v0.1.1...hushid-v0.1.2) (2026-11-15)


### Bug Fixes

* keep chat and MCP text intact ([#212](https://github.com/hushid/hushid/issues/212)) ([22ff985](https://github.com/hushid/hushid/commit/22ff985dbc3445c202a016ca3ce07fa50250a761))
* keep surrogate shape, local sinks, and upstream status ([#208](https://github.com/hushid/hushid/issues/208)) ([99183b5](https://github.com/hushid/hushid/commit/99183b5b1de13757bd83944f238fd8ed3282b5c6))
* put a RAMQ stand-in month and day in the detected slots ([#215](https://github.com/hushid/hushid/issues/215)) ([95d2aac](https://github.com/hushid/hushid/commit/95d2aac4ce04c1653529a0a726e33635c3b74f52))
* read a chat response that closes without a length ([#217](https://github.com/hushid/hushid/issues/217)) ([8d8aa01](https://github.com/hushid/hushid/commit/8d8aa0121669e3e5f3d0539d38824c2da0bd00a3))
* say which token has a non-UTF-8 surface ([#216](https://github.com/hushid/hushid/issues/216)) ([2dd3d63](https://github.com/hushid/hushid/commit/2dd3d63daba0d8ace843e413b47952069a35dafb))

## [0.1.1](https://github.com/hushid/hushid/compare/hushid-v0.1.0...hushid-v0.1.1) (2026-11-12)


### Features

* add a surrogate stand-in and a bracketed phone ([#203](https://github.com/hushid/hushid/issues/203)) ([df5319f](https://github.com/hushid/hushid/commit/df5319f2aaae9b5b4840f680342646bd7b216d99))
* add names, a mask, the proxy, and sealed transcripts ([#204](https://github.com/hushid/hushid/issues/204)) ([901fd75](https://github.com/hushid/hushid/commit/901fd75edcd4caef27173955230368b5233398f0))


### Bug Fixes

* classify every current host tool in judge ([#197](https://github.com/hushid/hushid/issues/197)) ([b0f86a9](https://github.com/hushid/hushid/commit/b0f86a9ed02534d5b7e12e0efeb07f0da2bd2507))
