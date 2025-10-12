## 2.7.1

**Release of package under new name**

- **fix**: add super.destroy() to SecretKeyData
- **fix**: remove Unnecessary casts
- **ci**: github release action
- **docs**: typo with X25519 Key Agreement example
- **chore**: pubspec - Add topic crypto
- **chore**: update js to 0.7.1 (was 0.6.7)

## 2.7.0

- Adds a cross-platform of Argon2id, a highly recommended algorithm for password hashing.
- Introduces a dependency on "package:ffi" (a package by Google). A memory allocator in the package
  is used when the Argon2 implementation distributes computation to multiple isolates.
- Small backwards-compatible changes in Blake2b and DartBlake2b API.

## 2.6.1

- Fixes incorrect base class constraints.

## 2.6.0

- Improves Blake2b/Blake2s support:
  - Adds support for using as a MAC algorithm
  - Adds support for custom output lengths
  - Improves test coverage
  - Fixes bugs
- Removes long-deprecated `newSink()` methods in `HashAlgorithm` and `MacAlgorithm` (so Blake2
  classes can implement both interfaces).
- Raises Dart SDK minimum to 3.1.0 and other small changes related to dependency constraints.
- Improves documentation.

## 2.5.0

- Adds enough DER encoding/decoding support for us to use Apple's CryptoKit ECDH/ECDSA functions.
- Improves BrowserHmac/etc. parameter checks.
- Improves documentation.

## 2.4.0

- Fixes many issues found by adding more tests. Also improves documentation.
- Improves performance of SHA256, HMAC, and PBKDF2 by cutting unnecessary state allocations and
  futures.
- Some small API refactoring and new class members that don't really affect the publicly visible
  API. We plan to address most API design issues (some discussed in the issue tracker) in the next
  major version (3.x).
- Adds support for seck256k1 key type ([#135](https://github.com/dint-dev/cryptography/pull/135)).

## 2.3.0

- Fixes some small issues.
- Improves documentation.

## 2.2.0

- The main changes in the the APIs:
  - Adds new elements and parameters in various classes, especially Dart implementations. This can
    be a breaking change if you extend those classes.
  - Adds _PaddingAlgorithm_ class and support for padding in AES-CBC.
  - Adds _CipherState_ class for processing long / infinite inputs.
  - Adds _CipherWand_, _KeyExchangeWand_, and _SignatureWand_ classes.
  - Adds random number generator parameters to class constructors. You can now have deterministic
    behavior in tests. For example, you can construct `BrowserCryptography(random: myRandom)`.
  - Adds an alternative random number generator, which is about 100 times faster than Random.secure.
    Random.secure continues to be the default everywhere.
  - Adds support for overwriting secrets in memory (_SecretKeyData_, _KeyPairData_) and eliminates
    unnecessary wrapping of bytes in unmodifiable lists.
  - Adds output buffer parameter for avoiding copying.
- The main changes in the Dart implementations:
  - Improves some ciphers such as _Chacha20_ and _AesCtr_ so that large inputs don't block the main
    thread. Instead, data will processed in chunks by default and other things can be scheduled
    in-between two chunks.
  - Significantly improves performance of Chacha20.poly1305.
- The main changes in the Web Cryptography implementations:
  - Fixes many bugs.
  - Adds support for fallbacks when browsers don't allow Web Cryptography (non-secure browser
    contexts).
- Improves documentation.

## 2.1.1

- Fixes small issues.
- Improves documentation.

## 2.1.0

- Improves performance of Blake2b/Blake2s.
- Add _SecretBoxPaddingError_ that is thrown when the padding of a secret box is invalid.
- Adds some additional constructors such as `DartAesGcm.with128bits`.
- Fixes various small issues.
- Improves documentation.

## 2.0.5

- Fixes bugs in `Xchacha20.poly1305`.

## 2.0.4

- Fixes an import of 'dart:io' that caused issues.

## 2.0.3

- Updates dependency constraints and linting rules.

## 2.0.2

- Fixes an issue in SecretBox.fromConcatenation.
- Improves documentation.

## 2.0.1

- Documentation fixes.

## 2.0.0

- Finishes null safety migration.

## 2.0.0-nullsafety.2

- For ease of use and backwards compatibility with 1.x, adds `SecretKey(bytes)` factory that
  just redirects to `SecretKeyData(bytes)`.
- Renames a few identifiers in _package:cryptography_ for consistency.
  Adds deprecation warnings to the old identifiers.
- Some small internal fixes.
- Improves documentation.

## 2.0.0-nullsafety.1

- Re-introduces _package:crypto_ as dependency now that a null-safe version exists.
- Better documentation.

## 2.0.0-nullsafety.0

- BREAKING CHANGES: Many breaking API changes that make the API easier to understand and use.
- IMPORTANT FIXES: Improves tests and fixes a number of bugs we spotted. We don't plan to support
  the 1.x API. We highly recommend you migrate to the 2.x API.
- The first null-safe version.

## 1.4.1

- Improves Web Cryptography support internally.
  - The implementation is now easier to read.
  - In older browsers, the implementation fall back to pure Dart implementation if attempt to
    use Web Cryptography fails.
  - HMAC and HKDF are now able to use Web Cryptography.
- Improves documentation.

## 1.4.0

- Adds support for _cryptography_flutter_, which uses operating system implementations.

## 1.3.0

- Adds PBKDF2 and Blake2b.
- Some internal refactoring.

## 1.2.1

- Fixes documentation issues.

## 1.2.0

- Adds `RsaPss` and `RsaPkcs1v15` (Web Cryptography only).
- BREAKING CHANGE: Recently added `JwkSecretKey` is now `EcJwkSecretKey`.
- Adds `EcJwkSecretKey` and `EcJwkPublicKey`.
- Adds `RsaJwkSecretKey` and `RsaJwkPublicKey`.

## 1.1.1

- Small fixes to documentation and internal declarations.

## 1.1.0

- BREAKING CHANGE: Cipher methods `encrypt` / `encryptSync` and `decrypt` / `decryptSync` now use
  return type `Future<Uint8List>` / `Uint8List` instead of previous `Future<List<int>>` /
  `List<int>`. We return instances of `Uint8List` anyway and we felt it's good to expose this
  fact despite despite possibility that the change affects some developers. If you are affected by
  this, you should see compile-time type warnings.
- `Cipher` has new getters `nonceLengthMin` and `nonceLengthMax`.
- AES-GCM is supported in the VM too.
- AES performance is improved significantly.
- Adds `JwkSecretKey`.
- BREAKING CHANGE: JwkSecretKey (instead of previous unspecified format) becomes the private key
  storage format for P-256/P-384/P-521. Any attempt to use the previous unspecified format will
  lead to errors. It's unlikely that anyone is affected by this change so we don't bump the major
  version.
- `SecretKey` and `SecretKey` now have property `Map<Object,Object> cachedValues`, which can
  be used for caching objects needed for cryptographic operations (such as handles to Web
  Cryptography API objects).
- Hides utils from developers.
- Internal refactoring.
- Better documentation.

## 1.0.4

- Internal refactoring. Splits a number of large source files (such as Web Cryptography support)
  into more readable smaller files.
- Adds VM implementation stubs for algorithms that are only supported in the browser (e.g.
  ecdhP256). The methods throw UnimplementedError in VM.
- Improves Poly1305 performance.
- Adds a few more tests.
- Improves documentation.

## 1.0.3

- Improves documentation.

## 1.0.2

- Implements automatic use of Web Cryptography API when SHA1 or SHA2 is used in browsers.
  SHA2-512 becomes up to 100 times faster in browsers. ED25519 becomes approximately 30 times
  faster in browsers with the improved SHA512.
- Better documentation and benchmarks.

## 1.0.1

- Implements `ed25519.newKeyFromSeed(seed)`.
- Significantly improves ED25519 performance.
- Small fixes in documentation.

## 1.0.0

- A stable API.

## 0.3.6

- Documentation fixes.

## 0.3.5

- Adds _Xchacha20_ cipher.
- When authenticated ciphers encounter incorrect MACs, they now throw `MacValidationException`
  (instead of returning null, which developers may ignore in some situations).

## 0.3.4

- Fixes a `cipher.name` issue and improves documentation.

## 0.3.3

- Improves documentation.
- Improves outputs of `cipher.name`.

## 0.3.2

- Improves documentation.

## 0.3.1

- Improves documentation.
- Eliminates AES-CBC and AES-CTR dependencies.

## 0.3.0

- Breaking changes: Removes separate key generator classes. Many API changes designed to reduce
  chances of developers using the API incorrectly.
- Adds HKDF and ED25519 support.
- Adds more assertions and tests.
- Improves documentation.

## 0.2.6

- Fixed an issue with dependency constraints that conflict with Flutter SDK.
- SecretKey / SecretKey property `bytes` is deprecated and replaced with `extract()` and
  `extractSync()` to better support implementations that protect the underlying bytes such as
  Web Cryptography API.
- Improves documentation.

## 0.2.5

- Adds AES for non-browser platforms.
- Fixes various bugs and improves test coverage.

## 0.2.4

- Improves documentation.

## 0.2.3

- Improves documentation, clarity, test coverage.

## 0.2.2

- Improves documentation.
- Deprecates ConstantTimeBytesEquality in favor of constantTimeBytesEquality.

## 0.2.1

- Improves documentation and stops exporting a few declarations.

## 0.2.0

- Major refactoring and breaking API changes.
- Improves in documentation.
- Adds AES, P256/P384/P521, SHA1, Poly1305, and AEAD_Chacha20_Poly1305.

## 0.1.2

- Improved documentation

## 0.1.1

- Fixed example

## 0.1.0

- Initial version
