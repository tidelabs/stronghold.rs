# Changelog

## \[0.3.0]

- Merged Store, Vault and Snapshot into a single crate called Stronghold-Engine.
  Merged utils-derive and communication-macros into a new crate called stronghold-derive
  Export Stronghold-derive through Stronghold-utils.
  - [36c8983](https://www.github.com/iotaledger/stronghold.rs/commit/36c8983eefd594c702a9e8b32bad25354ad127c0) merge derive/macro crates. on 2021-04-21
  - [b7d44f5](https://www.github.com/iotaledger/stronghold.rs/commit/b7d44f530e08be27128f25f46b4bb05cf3da99bd) update config. on 2021-04-21

## \[0.2.1]

- move stronghold-utils and add utils-derive for proc macros.
  rebuild vault and remove versioning.
  update client to use new vault.
  - [5490f0a](https://www.github.com/iotaledger/stronghold.rs/commit/5490f0aaaf58e5322a5569c02669514ec067b02f) refactor vault ([#181](https://www.github.com/iotaledger/stronghold.rs/pull/181)) on 2021-04-15

## \[0.2.0]

- Refactor the communication actor, enable using a relay peer, and integrate communication as feature into the stronghold interface.
  Remove unecessary Option/ Result wraps in `random` and `iota-stronghold`.
  Rename stronghold-test-utils to stronghold-utils and added riker ask pattern to it.
  - [9c7cba6](https://www.github.com/iotaledger/stronghold.rs/commit/9c7cba624e2a99f04a2d033b8673f8a4b8735f0b) Feat/integrate comms ([#130](https://www.github.com/iotaledger/stronghold.rs/pull/130)) on 2021-02-26
  - [fcb62bb](https://www.github.com/iotaledger/stronghold.rs/commit/fcb62bbf966bfcd543b13a79d73839a3fee0219e) fix/covector-2 ([#163](https://www.github.com/iotaledger/stronghold.rs/pull/163)) on 2021-03-12
