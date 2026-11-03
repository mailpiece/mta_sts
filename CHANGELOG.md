# Changelog

## Unreleased

- A malformed `Content-Length` is a failed fetch rather than an exception.

## 0.6.0

- The fetch ignores a proxy from the environment.
- The fetch's total timeout also bounds the response headers.

## 0.5.0

- Initial public release.