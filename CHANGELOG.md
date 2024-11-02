# Changelog

## Unreleased

### Added
- Mongoose v7.13 - v7.15 support ([#11](https://github.com/matth-x/MicroOcppMongoose/pull/11), [#14](https://github.com/matth-x/MicroOcppMongoose/pull/14))
- OCPP 2.0.1 Variables integration ([#13](https://github.com/matth-x/MicroOcppMongoose/pull/13), [#16](https://github.com/matth-x/MicroOcppMongoose/pull/16))

### Fixed
- AuthorizationKey hex conversion ([#12](https://github.com/matth-x/MicroOcppMongoose/pull/12), [#15](https://github.com/matth-x/MicroOcppMongoose/pull/15))

## [v1.1.0] - 2024-05-21

### Changed

- Adopt `bool isConnected()` from `Connection` interface ([#7](https://github.com/matth-x/MicroOcppMongoose/pull/7))
- Do not copy cert into heap memory ([#10](https://github.com/matth-x/MicroOcppMongoose/pull/10))
- Migrate to base64-encoder in Mongoose ([#4](https://github.com/matth-x/MicroOcppMongoose/pull/4))

### Added

- ~FTP over TLS support ([#3](https://github.com/matth-x/MicroOcppMongoose/pull/3))~ (see [#5](https://github.com/matth-x/MicroOcppMongoose/pull/5))
- OCPP 2.0.1 compatibility ([#6](https://github.com/matth-x/MicroOcppMongoose/pull/6))
- Send host name in TLS handshake ([#9](https://github.com/matth-x/MicroOcppMongoose/pull/9))

### Removed

- FTP moved into a new project [MicroFtp](https://github.com/matth-x/MicroFtp) ([#5](https://github.com/matth-x/MicroOcppMongoose/pull/5))
- Custom config `Cst_CaCert` ([#10](https://github.com/matth-x/MicroOcppMongoose/pull/10))

### Fixed

- Encode AuthorizationKey in Hex ([#4](https://github.com/matth-x/MicroOcppMongoose/pull/4))

## [1.0.0] - 2023-10-20

_First release._

### Changed

- Adopt Connection interface update
- Adopt Configuration API update (#1)
- Require manual apply for URL changes (#2)
- Adopt build flag prefix change from `MOCPP_` to `MO_`

## [d7617] - 23-08-23

_Previous point with breaking changes on master_

Renaming to MicroOcppMongoose is completed since this commit. See the [migration guide](https://matth-x.github.io/MicroOcpp/migration/) for more details on what's changed. Changelogs and semantic versioning are adopted starting with v1.0.0

## [0.1.0] - 23-08-20

_Last version under the project name ArduinoOcppMongoose_
