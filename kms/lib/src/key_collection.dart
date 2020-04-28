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

/// A collection of cryptographic key pairs and/or symmetric keys managed by
/// a [Kms].
abstract class KeyCollection {
  /// Returns a random hex string. By default, the length is 16 bytes.
  static String randomId({int length = 16}) {
    final random = Random.secure();
    final sb = StringBuffer();
    for (; length > 0; length--) {
      sb.write(random.nextInt(256).toRadixString(16).padLeft(2, '0'));
    }
    return sb.toString();
  }

  /// Key management service.
  Kms get kms;

  /// ID of this collection.
  String get collectionId;

  /// Creates a keypair for key exchange and/or signing.
  ///
  /// Throws [StateError] if you define [documentId] and the key already exists.
  Future<KeyDocument> createKeyPair({
    @required KeyExchangeType keyExchangeType,
    @required SignatureType signatureType,
    KeyDocumentSecurity keyDocumentSecurity,
    String documentId,
  });

  /// Creates a secret key for encrypting/decrypting.
  ///
  /// Throws [StateError] if you define [documentId] and the key already exists.
  Future<KeyDocument> createSecretKey({
    @required CipherType cipherType,
    KeyDocumentSecurity keyDocumentSecurity,
    String documentId,
  });

  Stream<KeyDocument> documentsAsStream() {
    return Stream<KeyDocument>.error(
      UnsupportedError('Operation is unsupported'),
    );
  }

  /// Chooses an existing cryptographic key document.
  KeyDocument document(String documentId);

  /// Deletes all cryptographic key documents.
  Future<void> deleteAll() async {
    await for (var document in documentsAsStream()) {
      await document.delete();
    }
  }
}
