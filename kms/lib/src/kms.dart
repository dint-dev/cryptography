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

import 'package:kms/kms.dart';

/// A Key Management Service (KMS) protects cryptographic keys and performs
/// cryptographic operations for you.
///
/// ## Example
/// ```
/// import 'package:kms/kms.dart';
///
/// final kms = MemoryKms();
///
/// Future<void> main() async {
///   // Create a cryptographic key with ID 'my signing key'
///   final document = kms.collection('example').createKeyPair(
///     documentId: 'my signing key',
///     signatureType: SignatureType.ed25519,
///     keyExchangeType: null,
///   );
///
///   // Sign
///   final signature = await document.sign('Signed document'.codePoints);
/// }
/// ```
abstract class Kms {
  /// Set of [CipherType] values supported by [createSecretKey].
  Set<CipherType> get supportedCipherTypes;

  /// Set of [KeyExchangeType] values supported by [createKeyPair].
  Set<KeyExchangeType> get supportedKeyExchangeTypes;

  /// Set of [SignatureType] values supported by [createKeyPair].
  Set<SignatureType> get supportedSignatureTypes;

  KeyDocumentSecurity get defaultKeyDocumentSecurity => null;

  /// Returns all cryptographic key collections.
  Stream<KeyCollection> collectionsAsStream();

  /// Returns all cryptographic keys.
  Stream<KeyDocument> documentsAsStream() {
    return collectionsAsStream()
        .asyncMap((collection) => collection.documentsAsStream())
        .asyncExpand((list) => list);
  }

  /// Returns the given cryptographic key collection.
  KeyCollection collection(String collectionId);
}

/// Thrown by [Kms] when a non-existing key is used.
class KeyDocumentDoesNotExistException implements Exception {
  final KeyDocument keyDocument;

  KeyDocumentDoesNotExistException(this.keyDocument);

  @override
  String toString() => 'Key does not exist: $keyDocument';
}
