## 2.3.4

- **fix**(iOS, MacOS): compilation issue, rename podspec
- **fix**(Android): Remove registrar build error on v1 plugin

## 2.3.3

**Release of package under new name**

- **fix**: AGP 8.x compatibility + Flutter 3.24

## 2.3.2

- Improves documentation.

## 2.3.1

- Raises Dart SDK minimum to 3.1.0 and other small changes related to dependency constraints.
- Fixes type inference warnings by Swift compiler.

## 2.3.0

- Adds support for algorithms. In this version, the following operating system API adapters pass
  tests:
  - Android:
    - FlutterAesGcm
    - FlutterChacha20.poly1305Aead()
    - FlutterHmac.sha1()
    - FlutterHmac.sha224()
    - FlutterHmac.sha256()
    - FlutterHmac.sha384()
    - FlutterHmac.sha512()
    - FlutterPbkdf2()
  - Apple operating systems:
    - FlutterAesGcm
    - FlutterChacha20.poly1305Aead()
    - FlutterEd25519()
    - FlutterEcdh.p256()
    - FlutterEcdh.p384()
    - FlutterEcdh.p521()
    - FlutterEcdsa.p256()
    - FlutterEcdsa.p384()
    - FlutterEcdsa.p521()
    - FlutterHmac.sha256()
    - FlutterHmac.sha512()
    - FlutterX25519()
- Requires "package:cryptography" 2.5.0, which has enough DER encoding/decoding support for us to
  use Apple's CryptoKit ECDH/ECDSA functions.
- Adds support for reading names of crypto providers in Android.
- Adds more tests.

## 2.2.0

- Makes the package use the new convention for enabling Flutter plugins. You no longer need to call
  `CryptographyFlutter.enable()` in your `main` function.
- Improves documentation.

## 2.1.1

- Bumps Kotlin Gradle plugin version.

## 2.1.0

- Many, major bug fixes.
- Some breaking changes to the API, but we decided not to increment the major version because we
  don't expect them to affect many developers (while we do want the bug fixes to reach everyone who
  uses the package).
- Many new features.
- We have a completely new test suite that ensures correctness and also reports performance with
  different input sizes.

## 2.0.2

- Fixes ["cryptography_flutter: Fix propagating error to Flutter + fix fallback to non-plugin encrypt/decrypt"](https://github.com/emz-hanauer/dart-cryptography/pull/76)
- Prints a debug message if a fallback to a Dart implementation happens because of an error.
- Updates dependency constraints and linting rules.

## 2.0.1

- Improves behavior in browsers.
- Improves documentation.

## 2.0.0

- Finishes null safety migration.

## 2.0.0-nullsafety.1

- Fixes SDK and dependency constraints.

## 2.0.0-nullsafety.0

- Upgrades to _package:cryptography_ version 2.x.
- Adds supports for AES and ChaCha20 in Android.

## 1.0.0

- Initial version
