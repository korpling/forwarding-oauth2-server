# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## Fixed

- Use `time` crate in tests instead of `chrono` crate because the latter one has
  outstanding security issues.

## [0.2.0] - 2022-07-14

### Fixed

- Updated `actix-web`, `jsonwebtoken`, `clap` and `simplelog` dependencies to
  their newest version.

## [0.1.0]

Initial release