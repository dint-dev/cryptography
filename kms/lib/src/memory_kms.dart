// Copyright 2019 Gohilla Ltd (https://gohilla.com).
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
import 'package:kms/kms.dart';
import 'package:meta/meta.dart';

/// An in-memory implementation of [Kms].
class MemoryKms extends KmsBase {
  /// Key exchange algorithms supported by default.
  static const Map<KeyExchangeType, KeyExchangeAlgorithm>
      defaultKeyExchangeAlgorithms = {
    KeyExchangeType.ecdhP256: ecdhP256,
    KeyExchangeType.x25519: x25519,
  };

  /// Digital signature algorithms supported by default.
  static const Map<SignatureType, SignatureAlgorithm>
      defaultSignatureAlgorithms = {
    SignatureType.ecdsaP256Sha256: ecdsaP256Sha256,
  };

  /// Ciphers supported by default.
  static const Map<CipherType, Cipher> defaultCiphers = {
    CipherType.aesCbc: aesCbc,
    CipherType.aesCtr32: aesCtr32,
    CipherType.aesGcm: aesGcm,
    CipherType.chacha20: chacha20,
  };
  final Map<KmsKey, _MemoryKmsValue> _values = <KmsKey, _MemoryKmsValue>{};

  final Map<KeyExchangeType, KeyExchangeAlgorithm> keyExchangeAlgorithms;

  final Map<SignatureType, SignatureAlgorithm> signatureAlgorithms;

  final Map<CipherType, Cipher> ciphers;

  /// Constructs a new KMS.
  ///
  /// You can optionally define algorithms supported by this KMS.
  MemoryKms({
    this.keyExchangeAlgorithms = defaultKeyExchangeAlgorithms,
    this.signatureAlgorithms = defaultSignatureAlgorithms,
    this.ciphers = defaultCiphers,
  });

  @override
  Set<CipherType> get supportedCipherTypes => ciphers.keys.toSet();

  @override
  Set<KeyExchangeType> get supportedKeyExchangeTypes =>
      keyExchangeAlgorithms.keys.toSet();

  @override
  Set<SignatureType> get supportedSignatureTypes =>
      signatureAlgorithms.keys.toSet();

  @override
  Future<KmsKey> createKeyPair({
    @required String keyRingId,
    @required KeyExchangeType keyExchangeType,
    @required SignatureType signatureType,
    String id,
  }) async {
    ArgumentError.checkNotNull(keyRingId);
    if (keyExchangeType == null && signatureType == null) {
      throw ArgumentError(
        'At least one of the following must be non-null: `keyExchangeType`, `signatureType`',
      );
    }

    KeyPair keyPair;
    SignatureAlgorithm signatureAlgorithm;
    KeyExchangeAlgorithm keyExchangeAlgorithm;

    if (keyExchangeType != null) {
      if (signatureType != null) {
        switch (keyExchangeType) {
          case KeyExchangeType.ecdhP256:
            if (signatureType != SignatureType.ecdsaP256Sha256) {
              throw ArgumentError.value(keyExchangeType);
            }
            break;
          case KeyExchangeType.ecdhP384:
            if (signatureType != SignatureType.ecdsaP384Sha384) {
              throw ArgumentError.value(keyExchangeType);
            }
            break;
          default:
            throw ArgumentError.value(keyExchangeType);
        }
      }
      keyExchangeAlgorithm = keyExchangeAlgorithms[keyExchangeType];
      if (keyExchangeAlgorithm == null) {
        throw StateError(
          'Key exchange algorithm "$signatureType" is unsupported by the KMS.',
        );
      }
      keyPair = await keyExchangeAlgorithm.keyPairGenerator.generate();
    }

    if (signatureType != null) {
      signatureAlgorithm = signatureAlgorithms[signatureType];
      if (signatureAlgorithm == null) {
        throw StateError(
          'Signature algorithm "$signatureType" is unsupported by the KMS.',
        );
      }
      keyPair ??= await signatureAlgorithm.keyPairGenerator.generate();
    }

    final kmsKey = id == null
        ? KmsKey.random(keyRingId: keyRingId)
        : KmsKey(keyRingId: keyRingId, id: id);

    if (_values.containsKey(kmsKey)) {
      throw StateError('The key already exists');
    }

    _values[kmsKey] = _MemoryKmsValue(
      keyPair: keyPair,
      keyExchangeAlgorithm: keyExchangeAlgorithm,
      signatureAlgorithm: signatureAlgorithm,
    );
    return kmsKey;
  }

  @override
  Future<KmsKey> createSecretKey({
    @required String keyRingId,
    @required CipherType cipherType,
    String id,
  }) async {
    ArgumentError.checkNotNull(keyRingId);
    ArgumentError.checkNotNull(cipherType);

    final cipher = ciphers[cipherType];
    if (cipher == null) {
      throw ArgumentError.value(cipherType, 'cipherType');
    }

    final secretKey = await cipher.secretKeyGenerator.generate();

    final kmsKey = id == null
        ? KmsKey.random(keyRingId: keyRingId)
        : KmsKey(keyRingId: keyRingId, id: id);

    if (_values.containsKey(kmsKey)) {
      throw StateError('The key already exists');
    }

    _values[kmsKey] = _MemoryKmsValue(
      secretKey: secretKey,
      cipher: cipher,
    );
    return kmsKey;
  }

  @override
  Future<List<int>> decrypt(
    List<int> bytes,
    KmsKey kmsKey, {
    @required Nonce nonce,
  }) {
    ArgumentError.checkNotNull(kmsKey);
    ArgumentError.checkNotNull(bytes);
    final value = _values[kmsKey];
    if (value == null) {
      throw KmsKeyDoesNotExistException(kmsKey);
    }
    final algorithm = value.cipher;
    if (algorithm == null) {
      throw ArgumentError.value(kmsKey, 'kmsKey');
    }
    return algorithm.decrypt(bytes, secretKey: value.secretKey, nonce: nonce);
  }

  @override
  Future<void> delete(KmsKey kmsKey) async {
    final values = _values;
    if (values[kmsKey] != null) {
      // We don't use remove() because we want to prevent recreating the same
      // key.
      values[kmsKey] = null;
    }
  }

  @override
  Future<List<int>> encrypt(
    List<int> bytes,
    KmsKey kmsKey, {
    @required Nonce nonce,
  }) async {
    ArgumentError.checkNotNull(kmsKey);
    ArgumentError.checkNotNull(bytes);
    final value = _values[kmsKey];
    if (value == null) {
      throw KmsKeyDoesNotExistException(kmsKey);
    }
    final algorithm = value.cipher;
    if (algorithm == null) {
      throw ArgumentError.value(kmsKey, 'kmsKey');
    }
    return algorithm.encrypt(bytes, secretKey: value.secretKey, nonce: nonce);
  }

  @override
  Stream<KmsKey> findAll({KmsKeyQuery query}) async* {
    final values = _values;
    for (var kmsKey in _values.keys.toList(growable: false)) {
      if (values[kmsKey] != null && (query == null || query.matches(kmsKey))) {
        yield (kmsKey);
      }
    }
  }

  @override
  Future<PublicKey> getPublicKey(KmsKey kmsKey) async {
    final value = _values[kmsKey];
    if (value == null) {
      throw KmsKeyDoesNotExistException(kmsKey);
    }
    final keyPair = value.keyPair;
    if (keyPair == null) {
      throw StateError('Not a key pair');
    }
    return keyPair.publicKey;
  }

  @override
  Future<SecretKey> sharedSecret(KmsKey kmsKey, PublicKey publicKey) async {
    ArgumentError.checkNotNull(kmsKey);
    ArgumentError.checkNotNull(publicKey);
    final value = _values[kmsKey];
    if (value == null) {
      throw KmsKeyDoesNotExistException(kmsKey);
    }
    final algorithm = value.keyExchangeAlgorithm;
    if (algorithm == null) {
      throw ArgumentError.value(kmsKey, 'kmsKey');
    }
    final secretKey = algorithm.sharedSecret(
      localPrivateKey: value.keyPair.privateKey,
      remotePublicKey: publicKey,
    );
    return secretKey;
  }

  @override
  Future<Signature> sign(
    List<int> bytes,
    KmsKey kmsKey,
  ) {
    ArgumentError.checkNotNull(bytes);
    ArgumentError.checkNotNull(kmsKey);
    final value = _values[kmsKey];
    if (value == null) {
      throw KmsKeyDoesNotExistException(kmsKey);
    }
    final algorithm = value.signatureAlgorithm;
    if (algorithm == null) {
      throw ArgumentError.value(kmsKey, 'kmsKey');
    }
    return algorithm.sign(bytes, value.keyPair);
  }

  @override
  Future<bool> verifySignature(
      List<int> bytes, Signature signature, KmsKey kmsKey) async {
    ArgumentError.checkNotNull(bytes);
    ArgumentError.checkNotNull(signature);
    final value = _values[kmsKey];
    if (value == null) {
      throw KmsKeyDoesNotExistException(kmsKey);
    }
    final algorithm = value.signatureAlgorithm;
    if (algorithm == null) {
      throw ArgumentError.value(kmsKey, 'kmsKey');
    }
    return algorithm.verify(bytes, signature);
  }
}

class _MemoryKmsValue {
  final KeyPair keyPair;
  final SecretKey secretKey;
  final KeyExchangeAlgorithm keyExchangeAlgorithm;
  final SignatureAlgorithm signatureAlgorithm;
  final Cipher cipher;

  _MemoryKmsValue({
    this.keyPair,
    this.secretKey,
    this.keyExchangeAlgorithm,
    this.signatureAlgorithm,
    this.cipher,
  });
}
