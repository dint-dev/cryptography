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
import 'package:kms/kms.dart';

/// A base class for [Kms] implementations.
abstract class KmsBase implements Kms {
  final Kms _kms;

  const KmsBase({Kms wrapped}) : _kms = wrapped;

  @override
  Set<CipherType> get supportedCipherTypes {
    if (_kms == null) {
      return const <CipherType>{};
    }
    return _kms.supportedCipherTypes;
  }

  @override
  Set<KeyExchangeType> get supportedKeyExchangeTypes {
    if (_kms == null) {
      return const <KeyExchangeType>{};
    }
    return _kms.supportedKeyExchangeTypes;
  }

  @override
  Set<SignatureType> get supportedSignatureTypes {
    if (_kms == null) {
      return const <SignatureType>{};
    }
    return _kms.supportedSignatureTypes;
  }

  @override
  Future<KmsKey> createKeyPair(
      {String keyRingId,
      KeyExchangeType keyExchangeType,
      SignatureType signatureType,
      String id}) {
    return _kms.createKeyPair(
      keyRingId: keyRingId,
      keyExchangeType: keyExchangeType,
      signatureType: signatureType,
      id: id,
    );
  }

  @override
  Future<KmsKey> createSecretKey(
      {String keyRingId, CipherType cipherType, String id}) {
    if (_kms == null) {
      return Future<KmsKey>.error(
        UnsupportedError('Operation is unsupported'),
      );
    }
    return _kms.createSecretKey(
      keyRingId: keyRingId,
      cipherType: cipherType,
      id: id,
    );
  }

  @override
  Future<List<int>> decrypt(
    List<int> cipherText,
    KmsKey kmsKey, {
    Nonce nonce,
    List<int> aad,
  }) {
    if (_kms == null) {
      return Future<List<int>>.error(
        UnsupportedError('Operation is unsupported'),
      );
    }
    return _kms.decrypt(cipherText, kmsKey, nonce: nonce, aad: aad);
  }

  @override
  Future<void> delete(KmsKey kmsKey) {
    if (_kms == null) {
      return Future<void>.error(
        UnsupportedError('Operation is unsupported'),
      );
    }
    return _kms.delete(kmsKey);
  }

  @override
  Future<List<int>> encrypt(
    List<int> bytes,
    KmsKey kmsKey, {
    Nonce nonce,
    List<int> aad,
  }) {
    if (_kms == null) {
      return Future<List<int>>.error(
        UnsupportedError('Operation is unsupported'),
      );
    }
    return _kms.encrypt(bytes, kmsKey, nonce: nonce, aad: aad);
  }

  @override
  Stream<KmsKey> findAll({KmsKeyQuery query}) {
    if (_kms == null) {
      return Stream<KmsKey>.error(
        UnsupportedError('Operation is unsupported'),
      );
    }
    return _kms.findAll(query: query);
  }

  @override
  Future<PublicKey> getPublicKey(KmsKey kmsKey) {
    if (_kms == null) {
      return Future<PublicKey>.error(
        UnsupportedError('Operation is unsupported'),
      );
    }
    return _kms.getPublicKey(kmsKey);
  }

  @override
  Future<SecretKey> sharedSecret(KmsKey kmsKey, PublicKey publicKey) {
    if (_kms == null) {
      return Future<SecretKey>.error(
        UnsupportedError('Operation is unsupported'),
      );
    }
    return _kms.sharedSecret(kmsKey, publicKey);
  }

  @override
  Future<Signature> sign(List<int> bytes, KmsKey kmsKey) {
    if (_kms == null) {
      return Future<Signature>.error(
        UnsupportedError('Operation is unsupported'),
      );
    }
    return _kms.sign(bytes, kmsKey);
  }

  @override
  Future<bool> verifySignature(
      List<int> bytes, Signature signature, KmsKey kmsKey) {
    if (_kms == null) {
      return Future<bool>.error(
        UnsupportedError('Operation is unsupported'),
      );
    }
    return _kms.verifySignature(bytes, signature, kmsKey);
  }
}
