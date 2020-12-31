// Copyright 2019-2020 Gohilla Ltd.
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

import 'package:cryptography/browser.dart';
import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart';

/// Returns cryptographic algorithm implementations.
///
/// ## Implementations
///   * [DartCryptography]
///   * [BrowserCryptography]
///   * [FlutterCryptography](https://pub.dev/documentation/cryptography_flutter/latest/cryptography_flutter/FlutterCryptography-class.html) (_package:cryptography_flutter_)
///
/// ## Setting implementation
/// In tests, you can set the static variable like this:
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// void main() {
///   setUp(() {
///     Cryptography.instance = yourInstance;
///   })
///
///   // ...
/// }
/// ```
///
/// In shipped application, it's a good practice to freeze the value of static
/// variable with [freezeInstance]:
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// void main() {
///   Cryptography.freezeInstance(yourInstance);
///
///   // ...
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

  AesCbc aesCbc({
    required MacAlgorithm macAlgorithm,
    int secretKeyLength = 32,
  });

  AesCtr aesCtr({
    required MacAlgorithm macAlgorithm,
    int secretKeyLength = 32,
    int counterBits = 64,
  });

  AesGcm aesGcm({
    int secretKeyLength = 32,
    int nonceLength = 12,
  });

  Argon2id argon2id({
    required int parallelism,
    required int memorySize,
    required int iterations,
    required int hashLength,
  });

  Blake2b blake2b();

  Blake2s blake2s();

  Chacha20 chacha20({required MacAlgorithm macAlgorithm});

  Chacha20 chacha20Poly1305Aead();

  Ecdh ecdhP256({required int length});

  Ecdh ecdhP384({required int length});

  Ecdh ecdhP521({required int length});

  Ecdsa ecdsaP256(HashAlgorithm hashAlgorithm);

  Ecdsa ecdsaP384(HashAlgorithm hashAlgorithm);

  Ecdsa ecdsaP521(HashAlgorithm hashAlgorithm);

  Ed25519 ed25519();

  Hchacha20 hchacha20();

  Hkdf hkdf({required Hmac hmac, required int outputLength});

  Hmac hmac(HashAlgorithm hashAlgorithm);

  Pbkdf2 pbkdf2({
    required MacAlgorithm macAlgorithm,
    required int iterations,
    required int bits,
  });

  Poly1305 poly1305();

  RsaPss rsaPss(HashAlgorithm hashAlgorithm, {required int nonceLengthInBytes});

  RsaSsaPkcs1v15 rsaSsaPkcs1v15(HashAlgorithm hashAlgorithm);

  Sha1 sha1();

  Sha224 sha224();

  Sha256 sha256();

  Sha384 sha384();

  Sha512 sha512();

  X25519 x25519();

  Xchacha20 xchacha20({required MacAlgorithm macAlgorithm});

  Xchacha20 xchacha20Poly1305Aead();

  /// Sets [Cryptography.instance] and prevents further mutations.
  static void freezeInstance(Cryptography cryptography) {
    Cryptography.instance = cryptography;
    _instanceFrozen = true;
  }
}
