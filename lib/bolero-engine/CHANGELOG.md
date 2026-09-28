# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.13.5](https://github.com/camshaft/bolero/compare/bolero-engine-v0.13.4...bolero-engine-v0.13.5) - 2026-09-28

### Added

- Add `RunPhase`, `update()`, `with_context()`, `shrink_enabled`, and `on_failure()` to `TestRunContext` ([#314](https://github.com/camshaft/bolero/pull/314))
- add test runtime context detection API ([#313](https://github.com/camshaft/bolero/pull/313))

### Other

- fix the check + test (1.68.0) jobs (clippy cleanup + MSRV-aware lockfile) ([#319](https://github.com/camshaft/bolero/pull/319))
- Set MSRV to 1.68 and pin indexmap to fix CI faliure ([#310](https://github.com/camshaft/bolero/pull/310))
- clippy fix and update MSRV to 1.82.0 ([#309](https://github.com/camshaft/bolero/pull/309))
