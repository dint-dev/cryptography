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

import 'dart:typed_data';

import '../../cryptography_plus.dart';

/// Delegating base class for [Cipher] implementations.
abstract class DelegatingCipher implements Cipher {
  Cipher get fallback;

  @override
  MacAlgorithm get macAlgorithm => fallback.macAlgorithm;

  @override
  int get nonceLength => fallback.nonceLength;

  @override
  int get secretKeyLength => fallback.secretKeyLength;

  @override
  int cipherTextLength(int clearTextLength) {
    return fallback.cipherTextLength(clearTextLength);
  }

  @override
  Future<List<int>> decrypt(
    SecretBox secretBox, {
    required SecretKey secretKey,
    List<int> aad = const <int>[],
    Uint8List? possibleBuffer,
  }) {
    return fallback.decrypt(
      secretBox,
      secretKey: secretKey,
      aad: aad,
    );
  }

  @override
  Future<SecretBox> encrypt(
    List<int> clearText, {
    required SecretKey secretKey,
    List<int>? nonce,
    List<int> aad = const <int>[],
    Uint8List? possibleBuffer,
  }) {
    return fallback.encrypt(
      clearText,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
    );
  }

  @override
  List<int> newNonce() => fallback.newNonce();

  @override
  Future<SecretKey> newSecretKey() {
    return fallback.newSecretKey();
  }

  @override
  Future<SecretKey> newSecretKeyFromBytes(List<int> bytes) {
    return fallback.newSecretKeyFromBytes(bytes);
  }
}

/// Delegating base class for [Cryptography] implementations.
abstract class DelegatingCryptography implements Cryptography {
  const DelegatingCryptography();

  Cryptography get fallback;

  @override
  AesCbc aesCbc({
    required MacAlgorithm macAlgorithm,
    PaddingAlgorithm paddingAlgorithm = PaddingAlgorithm.pkcs7,
    int secretKeyLength = 32,
  }) {
    return fallback.aesCbc(
      macAlgorithm: macAlgorithm,
      paddingAlgorithm: paddingAlgorithm,
      secretKeyLength: secretKeyLength,
    );
  }

  @override
  AesCtr aesCtr({
    required MacAlgorithm macAlgorithm,
    int secretKeyLength = 32,
    int counterBits = 64,
  }) {
    return fallback.aesCtr(
      macAlgorithm: macAlgorithm,
      secretKeyLength: secretKeyLength,
      counterBits: counterBits,
    );
  }

  @override
  AesGcm aesGcm({int secretKeyLength = 32, int nonceLength = 12}) {
    return fallback.aesGcm(
      secretKeyLength: secretKeyLength,
      nonceLength: nonceLength,
    );
  }

  @override
  Argon2id argon2id({
    required int memory,
    required int parallelism,
    required int iterations,
    required int hashLength,
  }) {
    return fallback.argon2id(
      memory: memory,
      parallelism: parallelism,
      iterations: iterations,
      hashLength: hashLength,
    );
  }

  @override
  Blake2b blake2b({int hashLengthInBytes = Blake2b.defaultHashLengthInBytes}) {
    return fallback.blake2b(
      hashLengthInBytes: hashLengthInBytes,
    );
  }

  @override
  Blake2s blake2s({int hashLengthInBytes = Blake2s.defaultHashLengthInBytes}) {
    return fallback.blake2s(
      hashLengthInBytes: hashLengthInBytes,
    );
  }

  @override
  Chacha20 chacha20({required MacAlgorithm macAlgorithm}) {
    return fallback.chacha20(macAlgorithm: macAlgorithm);
  }

  @override
  Chacha20 chacha20Poly1305Aead() {
    return fallback.chacha20Poly1305Aead();
  }

  @override
  Ecdh ecdhP256({required int length}) {
    return fallback.ecdhP256(length: length);
  }

  @override
  Ecdh ecdhP384({required int length}) {
    return fallback.ecdhP384(length: length);
  }

  @override
  Ecdh ecdhP521({required int length}) {
    return fallback.ecdhP521(length: length);
  }

  @override
  Ecdsa ecdsaP256(HashAlgorithm hashAlgorithm) {
    return fallback.ecdsaP256(hashAlgorithm);
  }

  @override
  Ecdsa ecdsaP384(HashAlgorithm hashAlgorithm) {
    return fallback.ecdsaP384(hashAlgorithm);
  }

  @override
  Ecdsa ecdsaP521(HashAlgorithm hashAlgorithm) {
    return fallback.ecdsaP521(hashAlgorithm);
  }

  @override
  Ed25519 ed25519() {
    return fallback.ed25519();
  }

  @override
  Hchacha20 hchacha20() {
    return fallback.hchacha20();
  }

  @override
  Hkdf hkdf({required Hmac hmac, required int outputLength}) {
    return fallback.hkdf(hmac: hmac, outputLength: outputLength);
  }

  @override
  Hmac hmac(HashAlgorithm hashAlgorithm) {
    return fallback.hmac(hashAlgorithm);
  }

  @override
  Pbkdf2 pbkdf2(
      {required MacAlgorithm macAlgorithm,
      required int iterations,
      required int bits}) {
    return fallback.pbkdf2(
      macAlgorithm: macAlgorithm,
      iterations: iterations,
      bits: bits,
    );
  }

  @override
  Poly1305 poly1305() {
    return fallback.poly1305();
  }

  @override
  RsaPss rsaPss(HashAlgorithm hashAlgorithm,
      {required int nonceLengthInBytes}) {
    return fallback.rsaPss(hashAlgorithm,
        nonceLengthInBytes: nonceLengthInBytes);
  }

  @override
  RsaSsaPkcs1v15 rsaSsaPkcs1v15(HashAlgorithm hashAlgorithm) {
    return fallback.rsaSsaPkcs1v15(hashAlgorithm);
  }

  @override
  Sha1 sha1() {
    return fallback.sha1();
  }

  @override
  Sha224 sha224() {
    return fallback.sha224();
  }

  @override
  Sha256 sha256() {
    return fallback.sha256();
  }

  @override
  Sha384 sha384() {
    return fallback.sha384();
  }

  @override
  Sha512 sha512() {
    return fallback.sha512();
  }

  @override
  X25519 x25519() {
    return fallback.x25519();
  }

  @override
  Xchacha20 xchacha20({required MacAlgorithm macAlgorithm}) {
    return fallback.xchacha20(macAlgorithm: macAlgorithm);
  }

  @override
  Xchacha20 xchacha20Poly1305Aead() {
    return fallback.xchacha20Poly1305Aead();
  }
}

/// Delegating base class for [Ecdh] implementations.
abstract class DelegatingEcdh extends DelegatingKeyExchangeAlgorithm
    implements Ecdh {
  const DelegatingEcdh();

  @override
  Ecdh get fallback;

  @override
  KeyPairType<KeyPairData, PublicKey> get keyPairType => fallback.keyPairType;

  @override
  Future<EcKeyPair> newKeyPair() {
    return fallback.newKeyPair();
  }

  @override
  Future<EcKeyPair> newKeyPairFromSeed(List<int> seed) {
    return fallback.newKeyPairFromSeed(seed);
  }
}

/// Delegating base class for [Ecdsa] implementations.
abstract class DelegatingEcdsa extends DelegatingSignatureAlgorithm
    implements Ecdsa {
  const DelegatingEcdsa();

  @override
  Ecdsa get fallback;

  @override
  HashAlgorithm get hashAlgorithm => fallback.hashAlgorithm;

  @override
  Future<EcKeyPair> newKeyPair() {
    return fallback.newKeyPair();
  }

  @override
  Future<EcKeyPair> newKeyPairFromSeed(List<int> seed) {
    return fallback.newKeyPairFromSeed(seed);
  }
}

/// Delegating base class for [Ed25519] implementations.
abstract class DelegatingEd25519 extends DelegatingSignatureAlgorithm
    implements Ed25519 {
  const DelegatingEd25519();

  @override
  Ed25519 get fallback;

  @override
  Future<SimpleKeyPair> newKeyPair() {
    return fallback.newKeyPair();
  }

  @override
  Future<SimpleKeyPair> newKeyPairFromSeed(List<int> seed) {
    return fallback.newKeyPairFromSeed(seed);
  }
}

/// Delegating base class for [KeyExchangeAlgorithm] implementations.
abstract class DelegatingKeyExchangeAlgorithm extends KeyExchangeAlgorithm {
  const DelegatingKeyExchangeAlgorithm();

  KeyExchangeAlgorithm get fallback;

  @override
  KeyPairType<KeyPairData, PublicKey> get keyPairType => fallback.keyPairType;

  @override
  Future<KeyPair> newKeyPair() {
    return fallback.newKeyPair();
  }

  @override
  Future<SecretKey> sharedSecretKey({
    required KeyPair keyPair,
    required PublicKey remotePublicKey,
  }) {
    return fallback.sharedSecretKey(
      keyPair: keyPair,
      remotePublicKey: remotePublicKey,
    );
  }
}

/// Delegating base class for [RsaPss] implementations.
abstract class DelegatingRsaPss extends DelegatingSignatureAlgorithm
    implements RsaPss {
  const DelegatingRsaPss();

  @override
  RsaPss get fallback;

  @override
  HashAlgorithm get hashAlgorithm => fallback.hashAlgorithm;

  @override
  int get nonceLengthInBytes => fallback.nonceLengthInBytes;

  @override
  Future<RsaKeyPair> newKeyPair({
    int modulusLength = RsaPss.defaultModulusLength,
    List<int> publicExponent = RsaPss.defaultPublicExponent,
  }) {
    return fallback.newKeyPair(
      modulusLength: modulusLength,
      publicExponent: publicExponent,
    );
  }
}

/// Delegating base class for [SignatureAlgorithm] implementations.
abstract class DelegatingSignatureAlgorithm extends SignatureAlgorithm {
  const DelegatingSignatureAlgorithm();

  SignatureAlgorithm get fallback;

  @override
  KeyPairType<KeyPairData, PublicKey> get keyPairType => fallback.keyPairType;

  @override
  Future<KeyPair> newKeyPair() {
    return fallback.newKeyPair();
  }

  @override
  Future<KeyPair> newKeyPairFromSeed(List<int> seed) {
    return fallback.newKeyPairFromSeed(seed);
  }

  @override
  Future<Signature> sign(List<int> message, {required KeyPair keyPair}) {
    return fallback.sign(message, keyPair: keyPair);
  }

  @override
  Future<bool> verify(List<int> message, {required Signature signature}) {
    return fallback.verify(message, signature: signature);
  }
}

/// Delegating base class for [StreamingCipher] implementations.
abstract class DelegatingStreamingCipher extends DelegatingCipher
    implements StreamingCipher {
  @override
  StreamingCipher get fallback;

  @override
  Future<List<int>> decrypt(
    SecretBox secretBox, {
    required SecretKey secretKey,
    List<int> aad = const <int>[],
    int keyStreamIndex = 0,
    Uint8List? possibleBuffer,
  }) {
    return fallback.decrypt(
      secretBox,
      secretKey: secretKey,
      aad: aad,
      keyStreamIndex: keyStreamIndex,
    );
  }

  @override
  Future<SecretBox> encrypt(
    List<int> clearText, {
    required SecretKey secretKey,
    List<int>? nonce,
    List<int> aad = const <int>[],
    int keyStreamIndex = 0,
    Uint8List? possibleBuffer,
  }) {
    return fallback.encrypt(
      clearText,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
      keyStreamIndex: keyStreamIndex,
    );
  }
}
