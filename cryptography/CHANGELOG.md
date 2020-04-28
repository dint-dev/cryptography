## 1.0.0
  * A stable API.

## 0.3.6
  * Documentation fixes.

## 0.3.5
  * Adds _XChaCha20_ cipher.
  * When authenticated ciphers encounter incorrect MACs, they now throw `MacValidationException`
    (instead of returning null, which developers may ignore in some situations).

## 0.3.4
  * Fixes a `cipher.name` issue and improves documentation.

## 0.3.3
  * Improves documentation.
  * Improves outputs of `cipher.name`.

## 0.3.2
  * Improves documentation.

## 0.3.1
  * Improves documentation.
  * Eliminates AES-CBC and AES-CTR dependencies.

## 0.3.0
  * Breaking changes: Removes separate key generator classes. Many API changes designed to reduce
    chances of developers using the API incorrectly.
  * Adds HKDF and ED25519 support.
  * Adds more assertions and tests.
  * Improves documentation.

## 0.2.6
  * Fixed an issue with dependency constraints that conflict with Flutter SDK.
  * PrivateKey / SecretKey property `bytes` is deprecated and replaced with `extract()` and
    `extractSync()` to better support implementations that protect the underlying bytes such as
    Web Cryptography API.
  * Improves documentation.

## 0.2.5
  * Adds AES for non-browser platforms.
  * Fixes various bugs and improves test coverage.

## 0.2.4
  * Improves documentation.

## 0.2.3
  * Improves documentation, clarity, test coverage.

## 0.2.2
  * Improves documentation.
  * Deprecates ConstantTimeBytesEquality in favor of constantTimeBytesEquality.

## 0.2.1
  * Improves documentation and stops exporting a few declarations.

## 0.2.0
  * Major refactoring and breaking API changes.
  * Improves in documentation.
  * Adds AES, P256/P384/P521, SHA1, Poly1305, and AEAD_Chacha20_Poly1305.

## 0.1.2
  * Improved documentation

## 0.1.1
  * Fixed example

## 0.1.0
  * Initial version