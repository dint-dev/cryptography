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

/// An implementation of [Cryptography] in pure Dart.
///
/// ## Algorithms
/// The following algorithms are supported:
///   * [AesCbc]
///   * [AesCtr]
///   * [AesGcm]
///   * [Blake2b]
///   * [Blake2s]
///   * [Chacha20]
///   * [Chacha20.poly1305Aead]
///   * [Ed25519]
///   * [Hmac]
///   * [Hkdf]
///   * [Pbkdf2]
///   * [Poly1305]
///   * [Sha1]
///   * [Sha224]
///   * [Sha256]
///   * [Sha384]
///   * [Sha512]
///   * [Xchacha20]
///   * [Xchacha20.poly1305Aead]
///   * [X25519]
///
/// SHA-1/SHA-2 implementations use [package:crypto](https://pub.dev/packages/crypto),
/// a package maintained by Google.
class DartCryptography extends Cryptography {
  static final DartCryptography defaultInstance = DartCryptography();

  final Random? _random;

  /// Constructs instance of [DartCryptography].
  ///
  /// If [random] is not given, a cryptographically secure random number
  /// generator (CSRNG) is used.
  DartCryptography({
    Random? random,
  }) : _random = random;

  @override
  AesCbc aesCbc({
    required MacAlgorithm macAlgorithm,
    PaddingAlgorithm paddingAlgorithm = PaddingAlgorithm.pkcs7,
    int secretKeyLength = 32,
  }) {
    return DartAesCbc(
      macAlgorithm: macAlgorithm,
      paddingAlgorithm: paddingAlgorithm,
      secretKeyLength: secretKeyLength,
      random: _random,
    );
  }

  @override
  AesCtr aesCtr({
    required MacAlgorithm macAlgorithm,
    int secretKeyLength = 32,
    int counterBits = AesCtr.defaultCounterBits,
  }) {
    return DartAesCtr(
      macAlgorithm: macAlgorithm,
      secretKeyLength: secretKeyLength,
      counterBits: counterBits,
      random: _random,
    );
  }

  @override
  AesGcm aesGcm({
    int secretKeyLength = 32,
    int nonceLength = 12,
  }) {
    return DartAesGcm(
      secretKeyLength: secretKeyLength,
      nonceLength: nonceLength,
      random: _random,
    );
  }

  @override
  Argon2id argon2id({
    required int memory,
    required int parallelism,
    required int iterations,
    required int hashLength,
  }) {
    return DartArgon2id(
      memory: memory,
      parallelism: parallelism,
      iterations: iterations,
      hashLength: hashLength,
    );
  }

  @override
  Blake2b blake2b({int hashLengthInBytes = 64}) {
    if (hashLengthInBytes == 64) {
      return const DartBlake2b();
    }
    return DartBlake2b(
      hashLengthInBytes: hashLengthInBytes,
    );
  }

  @override
  Blake2s blake2s({int hashLengthInBytes = 32}) {
    if (hashLengthInBytes == 64) {
      return const DartBlake2s();
    }
    return DartBlake2s(
      hashLengthInBytes: hashLengthInBytes,
    );
  }

  @override
  Chacha20 chacha20({required MacAlgorithm macAlgorithm}) {
    return DartChacha20(
      macAlgorithm: macAlgorithm,
      random: _random,
    );
  }

  @override
  Chacha20 chacha20Poly1305Aead() {
    return DartChacha20.poly1305Aead(
      random: _random,
    );
  }

  @override
  Ecdh ecdhP256({required int length}) {
    return DartEcdh.p256(
      random: _random,
    );
  }

  @override
  Ecdh ecdhP384({required int length}) {
    return DartEcdh.p384(
      random: _random,
    );
  }

  @override
  Ecdh ecdhP521({required int length}) {
    return DartEcdh.p521(
      random: _random,
    );
  }

  @override
  Ecdsa ecdsaP256(HashAlgorithm hashAlgorithm) {
    return DartEcdsa.p256(
      hashAlgorithm,
      random: _random,
    );
  }

  @override
  Ecdsa ecdsaP384(HashAlgorithm hashAlgorithm) {
    return DartEcdsa.p384(
      hashAlgorithm,
      random: _random,
    );
  }

  @override
  Ecdsa ecdsaP521(HashAlgorithm hashAlgorithm) {
    return DartEcdsa.p521(
      hashAlgorithm,
      random: _random,
    );
  }

  @override
  Ed25519 ed25519() {
    return DartEd25519(
      random: _random,
    );
  }

  @override
  Hchacha20 hchacha20() => DartHChacha20();

  @override
  Hkdf hkdf({required Hmac hmac, required int outputLength}) {
    return DartHkdf(hmac: hmac, outputLength: outputLength);
  }

  @override
  Hmac hmac(HashAlgorithm hashAlgorithm) {
    if (hashAlgorithm is DartSha1) {
      return const DartHmac(DartSha1());
    }
    if (hashAlgorithm is DartSha256) {
      return const DartHmac(DartSha256());
    }
    if (hashAlgorithm is DartSha384) {
      return const DartHmac(DartSha384());
    }
    if (hashAlgorithm is DartSha512) {
      return const DartHmac(DartSha512());
    }
    return DartHmac(hashAlgorithm);
  }

  @override
  Pbkdf2 pbkdf2({
    required MacAlgorithm macAlgorithm,
    required int iterations,
    required int bits,
  }) {
    return DartPbkdf2(
      macAlgorithm: macAlgorithm,
      iterations: iterations,
      bits: bits,
    );
  }

  @override
  Poly1305 poly1305() => const DartPoly1305();

  @override
  RsaPss rsaPss(
    HashAlgorithm hashAlgorithm, {
    required int nonceLengthInBytes,
  }) {
    return DartRsaPss(
      hashAlgorithm,
      nonceLengthInBytes: nonceLengthInBytes,
      random: _random,
    );
  }

  @override
  RsaSsaPkcs1v15 rsaSsaPkcs1v15(HashAlgorithm hashAlgorithm) {
    return DartRsaSsaPkcs1v15(
      hashAlgorithm,
      random: _random,
    );
  }

  @override
  Sha1 sha1() => const DartSha1();

  @override
  Sha224 sha224() => const DartSha224();

  @override
  Sha256 sha256() => const DartSha256();

  @override
  Sha384 sha384() => const DartSha384();

  @override
  Sha512 sha512() => const DartSha512();

  @override
  DartCryptography withRandom(Random? random) {
    return DartCryptography(random: random);
  }

  @override
  X25519 x25519() {
    return DartX25519(
      random: _random,
    );
  }

  @override
  Xchacha20 xchacha20({required MacAlgorithm macAlgorithm}) {
    return DartXchacha20(
      macAlgorithm: macAlgorithm,
      random: _random,
    );
  }

  @override
  Xchacha20 xchacha20Poly1305Aead() {
    return DartXchacha20.poly1305Aead(
      random: _random,
    );
  }
}
