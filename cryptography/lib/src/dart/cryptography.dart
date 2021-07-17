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

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart';

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
///   * [Chacha20Poly1305Aead]
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
///   * [Xchacha20Poly1305Aead]
///   * [X25519]
///
/// SHA-1/SHA-2 implementations use [package:crypto](https://pub.dev/packages/crypto),
/// a package maintained by Google.
class DartCryptography extends Cryptography {
  static final DartCryptography defaultInstance = DartCryptography();

  DartCryptography();

  @override
  AesCbc aesCbc({
    required MacAlgorithm macAlgorithm,
    int secretKeyLength = 32,
  }) {
    return DartAesCbc(
      macAlgorithm: macAlgorithm,
      secretKeyLength: secretKeyLength,
    );
  }

  @override
  AesCtr aesCtr({
    required MacAlgorithm macAlgorithm,
    int secretKeyLength = 32,
    int counterBits = 64,
  }) {
    return DartAesCtr(
      macAlgorithm: macAlgorithm,
      secretKeyLength: secretKeyLength,
      counterBits: counterBits,
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
    );
  }

  @override
  Argon2id argon2id({
    required int parallelism,
    required int memorySize,
    required int iterations,
    required int hashLength,
  }) {
    return DartArgon2id(
      parallelism: parallelism,
      memorySize: memorySize,
      iterations: iterations,
      hashLength: hashLength,
    );
  }

  @override
  Blake2b blake2b() => const DartBlake2b();

  @override
  Blake2s blake2s() => const DartBlake2s();

  @override
  Chacha20 chacha20({required MacAlgorithm macAlgorithm}) {
    return DartChacha20(
      macAlgorithm: macAlgorithm,
    );
  }

  @override
  Chacha20 chacha20Poly1305Aead() {
    return chacha20(macAlgorithm: DartChacha20Poly1305AeadMacAlgorithm());
  }

  @override
  Ecdh ecdhP256({required int length}) {
    throw UnimplementedError();
  }

  @override
  Ecdh ecdhP384({required int length}) {
    throw UnimplementedError();
  }

  @override
  Ecdh ecdhP521({required int length}) {
    throw UnimplementedError();
  }

  @override
  Ecdsa ecdsaP256(HashAlgorithm hashAlgorithm) {
    throw UnimplementedError();
  }

  @override
  Ecdsa ecdsaP384(HashAlgorithm hashAlgorithm) {
    throw UnimplementedError();
  }

  @override
  Ecdsa ecdsaP521(HashAlgorithm hashAlgorithm) {
    throw UnimplementedError();
  }

  @override
  Ed25519 ed25519() => DartEd25519();

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
    );
  }

  @override
  RsaSsaPkcs1v15 rsaSsaPkcs1v15(HashAlgorithm hashAlgorithm) {
    return DartRsaSsaPkcs1v15(hashAlgorithm);
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
  X25519 x25519() => const DartX25519();

  @override
  Xchacha20 xchacha20({required MacAlgorithm macAlgorithm}) {
    return DartXchacha20(
      macAlgorithm: macAlgorithm,
    );
  }

  @override
  Xchacha20 xchacha20Poly1305Aead() {
    return xchacha20(macAlgorithm: DartChacha20Poly1305AeadMacAlgorithm());
  }
}
