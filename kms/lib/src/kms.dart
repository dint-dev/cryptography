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
import 'package:meta/meta.dart';

/// A Key Management Service (KMS).
abstract class Kms {
  static Kms current = MemoryKms();

  /// Set of [CipherType] values supported by [createSecretKey].
  Set<CipherType> get supportedCipherTypes;

  /// Set of [KeyExchangeType] values supported by [createKeyPair].
  Set<KeyExchangeType> get supportedKeyExchangeTypes;

  /// Set of [SignatureType] values supported by [createKeyPair].
  Set<SignatureType> get supportedSignatureTypes;

  /// Creates a keypair for key exchange and/or signing.
  ///
  /// Throws [StateError] if you define [id] and the key already exists.
  Future<KmsKey> createKeyPair({
    @required String keyRingId,
    @required KeyExchangeType keyExchangeType,
    @required SignatureType signatureType,
    String id,
  });

  /// Creates a secret key for encrypting/decrypting.
  ///
  /// Throws [StateError] if you define [id] and the key already exists.
  Future<KmsKey> createSecretKey({
    @required String keyRingId,
    @required CipherType cipherType,
    String id,
  });

  /// Decrypts bytes.
  ///
  /// Throws [KmsKeyDoesNotExistException] if the key does not exist.
  /// Throws [StateError] if the key is invalid type.
  Future<List<int>> decrypt(
    List<int> bytes,
    KmsKey kmsKey, {
    @required Nonce nonce,
    List<int> aad,
  });

  /// Deletes a stored cryptographic key.
  ///
  /// Does not throw anything even if the key does not exist.
  Future<void> delete(KmsKey kmsKey);

  /// Encrypts bytes.
  ///
  /// Throws [KmsKeyDoesNotExistException] if the key does not exist.
  /// Throws [StateError] if the key is invalid type.
  Future<List<int>> encrypt(
    List<int> bytes,
    KmsKey kmsKey, {
    @required Nonce nonce,
    List<int> aad,
  });

  /// Returns all keys stored by the KMS.
  Stream<KmsKey> findAll({KmsKeyQuery query});

  /// Returns [PublicKey] of the key pair.
  ///
  /// Throws [KmsKeyDoesNotExistException] if the key does not exist.
  /// Throws [StateError] if the key is invalid type.
  Future<PublicKey> getPublicKey(KmsKey kmsKey);

  /// Calculates a shared [SecretKey] for communications between two parties.
  ///
  /// Throws [KmsKeyDoesNotExistException] if the key does not exist.
  /// Throws [StateError] if the key is invalid type.
  Future<SecretKey> sharedSecret(KmsKey kmsKey, PublicKey publicKey);

  /// Calculates [Signature] for the bytes.
  ///
  /// Throws [KmsKeyDoesNotExistException] if the key does not exist.
  /// Throws [StateError] if the key is invalid type.
  Future<Signature> sign(List<int> bytes, KmsKey kmsKey);

  /// Verifies a [Signature].
  Future<bool> verifySignature(
    List<int> bytes,
    Signature signature,
    KmsKey kmsKey,
  );
}

/// Thrown by [Kms] when a non-existing key is used.
class KmsKeyDoesNotExistException implements Exception {
  final KmsKey kmsKey;

  KmsKeyDoesNotExistException(this.kmsKey);

  @override
  String toString() => 'Key does not exist: $kmsKey';
}
