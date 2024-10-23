// Copyright 2019-2020 Gohilla.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import 'dart:math';

import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:cryptography_plus/dart.dart';

/// A factory for cryptographic algorithms.
///
/// This is used by factories in the cryptographic algorithm classes. For example,
/// [Chacha20.poly1305Aead] calls the [Cryptography.instance] method
/// [chacha20Poly1305Aead].
///
/// ## Implementations
///   * [DartCryptography]
///   * [BrowserCryptography]
///   * [FlutterCryptography](https://pub.dev/documentation/cryptography_flutter_plus/latest/cryptography_flutter/FlutterCryptography-class.html) (_package:cryptography_flutter_)
///
/// ## Setting implementation
///
/// In shipped application, it's a good practice to freeze the value of static
/// variable with [freezeInstance]:
/// ```
/// import 'package:cryptography_plus/cryptography_plus.dart';
///
/// void main() {
///   Cryptography.freezeInstance(yourInstance);
///
///   // ...
/// }
/// ```
///
/// ## Writing you own subclass
/// ```dart
/// import 'package:cryptography_plus/browser.dart';
/// import 'package:cryptography_plus/cryptography_plus.dart';
///
/// class MyCryptography extends BrowserCryptography {
///   @override
///   Sha256 get sha256 {
///     return SomeOtherSha256Implementation();
///   }
/// }
///
/// void main() {
///   // Change the default cryptography
///   Cryptography.freezeInstance(MyCryptography());
///
///   final sha256 = Sha256(); // --> SomeOtherSha256Implementation
/// }
/// ```
abstract class Cryptography {
  /// Default value of [instance].
  static final Cryptography defaultInstance =
      BrowserCryptography.defaultInstance;

  static bool _instanceFrozen = false;
  static Cryptography _instance = defaultInstance;

  /// Static variable that holds the [Cryptography] used by
  /// _package:cryptography_ classes.
  ///
  /// See [Cryptography] documentation.
  static Cryptography get instance => _instance;

  static set instance(Cryptography cryptography) {
    if (_instanceFrozen && _instance != cryptography) {
      throw StateError(
        '`Cryptography.instance=` failed because a different implementation has been frozen.',
      );
    }
    _instance = cryptography;
  }

  const Cryptography();

  /// A factory used by [AesCbc].
  AesCbc aesCbc({
    required MacAlgorithm macAlgorithm,
    PaddingAlgorithm paddingAlgorithm = PaddingAlgorithm.pkcs7,
    int secretKeyLength = 32,
  });

  /// A factory used by [AesCtr].
  AesCtr aesCtr({
    required MacAlgorithm macAlgorithm,
    int secretKeyLength = 32,
    int counterBits = 64,
  });

  /// A factory used by [AesGcm].
  AesGcm aesGcm({
    int secretKeyLength = 32,
    int nonceLength = 12,
  });

  /// A factory used by [Argon2id].
  Argon2id argon2id({
    required int memory,
    required int parallelism,
    required int iterations,
    required int hashLength,
  });

  /// A factory used by [Blake2b].
  Blake2b blake2b({int hashLengthInBytes = 64});

  /// A factory used by [Blake2s].
  Blake2s blake2s({int hashLengthInBytes = 32});

  /// A factory used by [Chacha20].
  Chacha20 chacha20({required MacAlgorithm macAlgorithm});

  /// A factory used by [Chacha20.poly1305Aead].
  Chacha20 chacha20Poly1305Aead();

  /// A factory used by [Ecdh.p256].
  Ecdh ecdhP256({required int length});

  /// A factory used by [Ecdh.p384].
  Ecdh ecdhP384({required int length});

  /// A factory used by [Ecdh.p521].
  Ecdh ecdhP521({required int length});

  /// A factory used by [Ecdsa.p256].
  Ecdsa ecdsaP256(HashAlgorithm hashAlgorithm);

  /// A factory used by [Ecdsa.p384].
  Ecdsa ecdsaP384(HashAlgorithm hashAlgorithm);

  /// A factory used by [Ecdsa.p521].
  Ecdsa ecdsaP521(HashAlgorithm hashAlgorithm);

  /// A factory used by [Ed25519].
  Ed25519 ed25519();

  /// A factory used by [Hchacha20].
  Hchacha20 hchacha20();

  /// A factory used by [Hkdf].
  Hkdf hkdf({required Hmac hmac, required int outputLength});

  /// A factory used by [Hmac].
  Hmac hmac(HashAlgorithm hashAlgorithm);

  /// A factory used by [Pbkdf2].
  Pbkdf2 pbkdf2({
    required MacAlgorithm macAlgorithm,
    required int iterations,
    required int bits,
  });

  /// A factory used by [Poly1305].
  Poly1305 poly1305();

  /// A factory used by [RsaPss].
  RsaPss rsaPss(HashAlgorithm hashAlgorithm, {required int nonceLengthInBytes});

  /// A factory used by [RsaSsaPkcs1v15].
  RsaSsaPkcs1v15 rsaSsaPkcs1v15(HashAlgorithm hashAlgorithm);

  /// A factory used by [Sha1].
  Sha1 sha1();

  /// A factory used by [Sha224].
  Sha224 sha224();

  /// A factory used by [Sha256].
  Sha256 sha256();

  /// A factory used by [Sha384].
  Sha384 sha384();

  /// A factory used by [Sha512].
  Sha512 sha512();

  Cryptography withRandom(Random random);

  /// A factory used by [X25519].
  X25519 x25519();

  /// A factory used by [Xchacha20].
  Xchacha20 xchacha20({required MacAlgorithm macAlgorithm});

  /// A factory used by [Xchacha20.poly1305Aead].
  Xchacha20 xchacha20Poly1305Aead();

  /// Sets [Cryptography.instance] and prevents further mutations.
  static void freezeInstance(Cryptography cryptography) {
    Cryptography.instance = cryptography;
    _instanceFrozen = true;
  }
}
