## 1.1.0
  * BREAKING CHANGE: Cipher methods `encrypt` / `encryptSync` and `decrypt` / `decryptSync` now use
    return type `Future<Uint8List>` / `Uint8List` instead of previous `Future<List<int>>` /
    `List<int>`. We return instances of `Uint8List` anyway and we felt it's good to expose this
    fact despite despite possibility that the change affects some developers. If you are affected by
    this, you should see compile-time type warnings.
  * `Cipher` has new getters `nonceLengthMin` and `nonceLengthMax`.
  * AES-GCM is supported in the VM too.
  * AES performance is improved significantly.
  * Adds `JwkPrivateKey`.
  * BREAKING CHANGE: JwkPrivateKey (instead of previous unspecified format) becomes the private key
    storage format for P-256/P-384/P-521. Any attempt to use the previous unspecified format will
    lead to errors. It's unlikely that anyone is affected by this change so we don't bump the major
    version.
  * `SecretKey` and `PrivateKey` now have property `Map<Object,Object> cachedValues`, which can
    be used for caching objects needed for cryptographic operations (such as handles to Web
    Cryptography API objects).
  * Hides utils from developers.
  * Internal refactoring.

## 1.0.4
  * Internal refactoring. Splits a number of large source files (such as Web Cryptography support)
    into more readable smaller files.
  * Adds VM implementation stubs for algorithms that are only supported in the browser (e.g.
    ecdhP256). The methods throw UnimplementedError in VM.
  * Improves Poly1305 performance.
  * Adds a few more tests.
  * Improves documentation.

## 1.0.3
  * Improves documentation.

## 1.0.2
  * Implements automatic use of Web Cryptography API when SHA1 or SHA2 is used in browsers.
    SHA2-512 becomes up to 100 times faster in browsers. ED25519 becomes approximately 30 times
    faster in browsers with the improved SHA512.
  * Better documentation and benchmarks.

## 1.0.1
  * Implements `ed25519.newKeyPairFromSeed(seed)`.
  * Significantly improves ED25519 performance.
  * Small fixes in documentation.

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