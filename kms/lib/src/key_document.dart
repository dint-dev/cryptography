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

import 'dart:math';

import 'package:kms/kms.dart';
import 'package:meta/meta.dart';

/// A cryptographic key pair or symmetric key managed by a [Kms].
abstract class KeyDocument {
  /// Key collection.
  KeyCollection get collection;

  /// Key ID in the key ring.
  String get documentId;

  /// Decrypts the message.
  ///
  /// Throws [KeyDocumentDoesNotExistException] if the cryptographic key does
  /// not exist.
  /// Throws [StateError] if the cryptographic key has an invalid type.
  ///
  /// ## Example
  /// ```
  /// import 'package:cryptography/cryptography.dart';
  /// import 'package:kms/kms.dart';
  ///
  /// final kms = MemoryKms();
  ///
  /// Future<void> main() async {
  ///   // Create a cryptographic key with ID 'my signing key'
  ///   final document = kms.collection('example').createSecretKey(
  ///     documentId: 'my signing key',
  ///     cipherType: CipherType.aesGcm,
  ///   );
  ///
  ///   // Choose some unique nonce (initialization vector, IV)
  ///   final nonce = aesGcm.newNonce();
  ///
  ///   // Encrypt
  ///   final encrypted = await document.encrypt(
  ///     'Encrypted data'.codePoints,
  ///     nonce: nonce,
  ///   );
  ///
  ///   // Decrypt
  ///   final decrypted = await document.decrypt(
  ///     encrypted,
  ///     nonce: nonce,
  ///   );
  /// }
  /// ```
  Future<List<int>> decrypt(
    List<int> message, {
    @required Nonce nonce,
    List<int> aad,
  });

  /// Deletes a stored cryptographic key.
  ///
  /// Does not throw anything even if the key does not exist.
  Future<void> delete();

  /// Encrypts the message.
  ///
  /// Throws [KeyDocumentDoesNotExistException] if the cryptographic key does
  /// not exist.
  /// Throws [StateError] if the cryptographic key has an invalid type.
  ///
  /// ## Example
  /// ```
  /// import 'package:cryptography/cryptography.dart';
  /// import 'package:kms/kms.dart';
  ///
  /// final kms = MemoryKms();
  ///
  /// Future<void> main() async {
  ///   // Create a cryptographic key with ID 'my signing key'
  ///   final document = kms.collection('example').createSecretKey(
  ///     documentId: 'my signing key',
  ///     cipherType: CipherType.aesGcm,
  ///   );
  ///
  ///   // Choose some unique nonce (initialization vector, IV)
  ///   final nonce = aesGcm.newNonce();
  ///
  ///   // Encrypt
  ///   final encrypted = await document.encrypt(
  ///     'Encrypted data'.codePoints,
  ///     nonce: nonce,
  ///   );
  ///
  ///   // Decrypt
  ///   final decrypted = await document.decrypt(
  ///     encrypted,
  ///     nonce: nonce,
  ///   );
  /// }
  /// ```
  Future<List<int>> encrypt(
    List<int> message, {
    @required Nonce nonce,
    List<int> aad,
  });

  /// Returns [PublicKey] of the key pair.
  ///
  /// Throws [KeyDocumentDoesNotExistException] if the cryptographic key does
  /// not exist.
  /// Throws [StateError] if the cryptographic key is invalid type.
  Future<PublicKey> getPublicKey();

  /// Uses a key agreement agreement algorithm to produce a [SecretKey] that
  /// only the two parties can calculate.
  ///
  /// The inputs are the [PrivateKey] managed by the KMS and the [PublicKey] of
  /// the remote peer.
  ///
  /// Throws [KeyDocumentDoesNotExistException] if the cryptographic key does
  /// not exist.
  /// Throws [StateError] if the cryptographic key has an invalid type.
  ///
  /// ## Example
  /// ```
  /// import 'package:cryptography/cryptography.dart';
  /// import 'package:kms/kms.dart';
  ///
  /// final kms = MemoryKms();
  ///
  /// Future<void> main() async {
  ///   // Create a cryptographic key with ID 'my key pair'
  ///   final document = kms.collection('example').createKeyPair(
  ///     documentId: 'my key pair',
  ///     signatureType: null,
  ///     keyExchangeType: KeyExchangeType.x25519,
  ///   );
  ///
  ///   // In this example, our counter-party has some random public key.
  ///   final remotePublicKey = x25519.newKeyPairSync().publicKey;
  ///
  ///   // Perform key agreement
  ///   final secretKey = await document.sharedSecret(
  ///     remotePublicKey: remotePublicKey,
  ///   );
  ///   print('Secret key: ${secretKey.extractSync()}');
  ///
  ///   // Delete key
  ///   document.delete();
  /// }
  /// ```
  Future<SecretKey> sharedSecret({@required PublicKey remotePublicKey});

  /// Calculates [Signature] for the message
  ///
  /// Throws [KeyDocumentDoesNotExistException] if the cryptographic key does
  /// not exist.
  /// Throws [StateError] if the cryptographic key has an invalid type.
  ///
  /// ## Example
  /// ```
  /// import 'package:kms/kms.dart';
  ///
  /// final kms = MemoryKms();
  ///
  /// Future<void> main() async {
  ///   // Create a cryptographic key with ID 'my key pair'
  ///   final document = kms.collection('example').createKeyPair(
  ///     documentId: 'my key pair',
  ///     signatureType: SignatureType.ed25519,
  ///     keyExchangeType: null,
  ///   );
  ///
  ///   // Signed message
  ///   final message = 'Signed document'.codePoints;
  ///
  ///   // Request a signature from the KMS
  ///   final signature = await document.sign(message);
  ///
  ///   // Delete the key pair.
  ///   // In real applications, you would store keys for longer time.
  ///   await document.delete();
  /// }
  /// ```
  Future<Signature> sign(List<int> message);

  @override
  int get hashCode => collection.hashCode ^ documentId.hashCode;

  @override
  bool operator ==(other) =>
      other is KeyDocument &&
      collection == other.collection &&
      documentId == other.documentId;

  @override
  String toString() =>
      'kms.collection("${collection.collectionId}").document(${documentId})';

  /// Returns a random hex string. By default, the length is 16 bytes.
  static String randomId({int length = 16}) {
    final random = Random.secure();
    final sb = StringBuffer();
    for (; length > 0; length--) {
      sb.write(random.nextInt(256).toRadixString(16).padLeft(2, '0'));
    }
    return sb.toString();
  }
}
