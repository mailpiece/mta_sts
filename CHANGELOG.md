# Changelog

## Unreleased

- A malformed `Content-Length` is a failed fetch rather than an exception.
- The fetch reads at most 128 KB, headers included.
- A name too long for DNS is no longer converted from Unicode.
- A recipient domain that isn't a hostname is `none` without a lookup.

## 0.6.0

- The fetch ignores a proxy from the environment.
- The fetch's total timeout also bounds the response headers.

## 0.5.0

- Initial public release.