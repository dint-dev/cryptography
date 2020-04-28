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

/// An in-memory implementation of [Kms]. Useful for unit tests.
class MemoryKms extends Kms {
  final Map<String, _MemoryKeyCollection> _collections =
      <String, _MemoryKeyCollection>{};

  final Map<KeyExchangeType, KeyExchangeAlgorithm> keyExchangeAlgorithms;

  final Map<SignatureType, SignatureAlgorithm> signatureAlgorithms;

  final Map<CipherType, Cipher> ciphers;

  @override
  final KeyDocumentSecurity defaultKeyDocumentSecurity;

  /// Constructs a new KMS.
  ///
  /// You can optionally define algorithms supported by this KMS.
  MemoryKms({
    this.keyExchangeAlgorithms = defaultKeyExchangeImplementations,
    this.signatureAlgorithms = defaultSignatureImplementations,
    this.ciphers = defaultCipherImplementations,
    this.defaultKeyDocumentSecurity,
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
  Stream<KeyCollection> collectionsAsStream() {
    return Stream<KeyCollection>.fromIterable(_collections.values);
  }

  @override
  KeyCollection collection(String collectionId) {
    return _collections[collectionId] ??
        _MemoryKeyCollection(this, collectionId, false);
  }
}

class _MemoryKeyCollection extends KeyCollection {
  @override
  final MemoryKms kms;

  @override
  final String collectionId;

  final Map<String, _MemoryKeyDocument> _documents =
      <String, _MemoryKeyDocument>{};

  bool _exists = false;

  @override
  KeyDocument document(String documentId) {
    ArgumentError.checkNotNull(documentId, 'documentId');
    return _instance()._documents[documentId] ??
        _MemoryKeyDocument(this, documentId);
  }

  @override
  Future<void> deleteAll() async {
    _instance()?._documents?.clear();
  }

  /// Returns the real instance.
  _MemoryKeyCollection _instance() {
    if (_exists) {
      return this;
    }
    if (kms._collections.containsKey(collectionId)) {
      return kms._collections[collectionId];
    }
    kms._collections[collectionId] = this;
    _exists = true;
    return this;
  }

  _MemoryKeyCollection(this.kms, this.collectionId, this._exists);

  @override
  Future<KeyDocument> createKeyPair({
    @required KeyExchangeType keyExchangeType,
    @required SignatureType signatureType,
    KeyDocumentSecurity keyDocumentSecurity,
    String documentId,
  }) async {
    if (keyExchangeType == null && signatureType == null) {
      throw ArgumentError(
        'At least one of the following must be non-null: `keyExchangeType`, `signatureType`',
      );
    }
    documentId ??= KeyDocument.randomId();

    KeyPair keyPair;
    SignatureAlgorithm signatureAlgorithm;
    KeyExchangeAlgorithm keyExchangeAlgorithm;

    if (keyExchangeType != null) {
      if (signatureType != null) {
        switch (keyExchangeType) {
          case KeyExchangeType.ecdhP256:
            if (signatureType != SignatureType.ecdsaP256sha256) {
              throw ArgumentError.value(keyExchangeType);
            }
            break;
          default:
            throw ArgumentError.value(keyExchangeType);
        }
      }
      keyExchangeAlgorithm = kms.keyExchangeAlgorithms[keyExchangeType];
      if (keyExchangeAlgorithm == null) {
        throw StateError(
          'Key exchange algorithm "$signatureType" is unsupported by the KMS.',
        );
      }
      keyPair = await keyExchangeAlgorithm.newKeyPair();
    }

    if (signatureType != null) {
      signatureAlgorithm = kms.signatureAlgorithms[signatureType];
      if (signatureAlgorithm == null) {
        throw StateError(
          'Signature algorithm "$signatureType" is unsupported by the KMS.',
        );
      }
      keyPair ??= await signatureAlgorithm.newKeyPair();
    }
    final instance = _instance();
    if (instance._documents.containsKey(documentId)) {
      throw StateError('The key already exists');
    }
    final document = _MemoryKeyDocument(
      this,
      documentId,
      keyPair: keyPair,
      keyExchangeAlgorithm: keyExchangeAlgorithm,
      signatureAlgorithm: signatureAlgorithm,
    );
    instance._documents[documentId] = document;
    return document;
  }

  @override
  Future<KeyDocument> createSecretKey({
    @required CipherType cipherType,
    KeyDocumentSecurity keyDocumentSecurity,
    String documentId,
  }) async {
    ArgumentError.checkNotNull(cipherType);
    documentId ??= KeyDocument.randomId();
    final cipher = kms.ciphers[cipherType];
    if (cipher == null) {
      throw ArgumentError.value(cipherType, 'cipherType');
    }
    final instance = _instance();
    if (instance._documents.containsKey(documentId)) {
      throw StateError('The key already exists');
    }
    final secretKey = await cipher.newSecretKey();
    final document = _MemoryKeyDocument(
      this,
      documentId,
      secretKey: secretKey,
      cipher: cipher,
    );
    instance._documents[documentId] = document;
    return document;
  }
}

class _MemoryKeyDocument extends KeyDocument {
  /// Returns the real instance.
  _MemoryKeyDocument _instance() {
    if (_exists) {
      return this;
    }
    if (collection._documents.containsKey(documentId)) {
      return collection._documents[documentId];
    }
    collection._documents[documentId] = this;
    _exists = true;
    return this;
  }

  @override
  final _MemoryKeyCollection collection;

  @override
  final String documentId;
  bool _exists = false;

  final KeyPair keyPair;
  final SecretKey secretKey;
  final KeyExchangeAlgorithm keyExchangeAlgorithm;
  final SignatureAlgorithm signatureAlgorithm;
  final Cipher cipher;
  final KeyDocumentSecurity keyDocumentSecurity;

  _MemoryKeyDocument(
    this.collection,
    this.documentId, {
    this.keyPair,
    this.secretKey,
    this.keyExchangeAlgorithm,
    this.signatureAlgorithm,
    this.cipher,
    this.keyDocumentSecurity,
  });

  @override
  Future<List<int>> decrypt(
    List<int> cipherText, {
    @required Nonce nonce,
    List<int> aad,
  }) async {
    ArgumentError.checkNotNull(cipherText);
    final instance = _instance();
    if (instance == null) {
      throw KeyDocumentDoesNotExistException(this);
    }
    final cipher = instance.cipher;
    if (cipher == null) {
      throw StateError('Not a symmetric key');
    }
    return cipher.decrypt(
      cipherText,
      secretKey: instance.secretKey,
      nonce: nonce,
      aad: aad,
    );
  }

  @override
  Future<void> delete() async {
    collection._documents[documentId] = null;
  }

  @override
  Future<List<int>> encrypt(
    List<int> clearText, {
    @required Nonce nonce,
    List<int> aad,
  }) async {
    ArgumentError.checkNotNull(clearText, 'clearText');
    ArgumentError.checkNotNull(nonce, 'nonce');
    final instance = _instance();
    if (instance == null) {
      throw KeyDocumentDoesNotExistException(this);
    }
    final cipher = instance.cipher;
    if (cipher == null) {
      throw StateError('Not a symmetric key');
    }
    return cipher.encrypt(
      clearText,
      secretKey: instance.secretKey,
      nonce: nonce,
      aad: aad,
    );
  }

  @override
  Future<PublicKey> getPublicKey() async {
    final instance = _instance();
    if (instance == null) {
      throw KeyDocumentDoesNotExistException(this);
    }
    final keyPair = instance.keyPair;
    if (keyPair == null) {
      throw StateError('Not a key pair');
    }
    return keyPair.publicKey;
  }

  @override
  Future<SecretKey> sharedSecret({
    @required PublicKey remotePublicKey,
  }) async {
    ArgumentError.checkNotNull(remotePublicKey);
    final instance = _instance();
    if (instance == null) {
      throw KeyDocumentDoesNotExistException(this);
    }
    final algorithm = instance.keyExchangeAlgorithm;
    if (algorithm == null) {
      throw StateError('Not a key pair for key exchange');
    }
    final secretKey = algorithm.sharedSecret(
      localPrivateKey: instance.keyPair.privateKey,
      remotePublicKey: remotePublicKey,
    );
    return secretKey;
  }

  @override
  Future<Signature> sign(List<int> bytes) {
    ArgumentError.checkNotNull(bytes);
    final instance = _instance();
    if (instance == null) {
      throw KeyDocumentDoesNotExistException(this);
    }
    final algorithm = instance.signatureAlgorithm;
    if (algorithm == null) {
      throw StateError('Not key pair for a signing');
    }
    return algorithm.sign(bytes, instance.keyPair);
  }
}
