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

import 'dart:async';
import 'dart:convert';
import 'dart:html' as html;

import 'package:cryptography/cryptography.dart';
import 'package:kms/kms.dart';
import 'package:meta/meta.dart';

Kms newBrowserKms({String namespace, SecretKey secretKey}) {
  return BrowserKmsImpl(namespace: namespace, secretKey: secretKey);
}

class BrowserKmsImpl extends Kms implements BrowserKms {
  final String namespace;

  final SecretKey _secretKey;

  BrowserKmsImpl({this.namespace, SecretKey secretKey})
      : _secretKey = secretKey;

  @override
  Set<CipherType> get supportedCipherTypes =>
      defaultCipherImplementations.keys.toSet();

  @override
  Set<KeyExchangeType> get supportedKeyExchangeTypes =>
      defaultKeyExchangeImplementations.keys.toSet();

  @override
  Set<SignatureType> get supportedSignatureTypes =>
      defaultSignatureImplementations.keys.toSet();

  @override
  KeyCollection collection(String collectionId) {
    return _BrowserKeyCollection(this, collectionId);
  }

  @override
  Stream<KeyCollection> collectionsAsStream() async* {
    final json = await _load();
    for (var key in json.keys) {
      yield (collection(key));
    }
  }

  Future<Map<String, Object>> _load() async {
    final namespace = this.namespace ?? 'default';
    final key = 'kms:$namespace';
    final value = html.window.localStorage[key];
    if (value is String) {
      if (value.trim().startsWith('{')) {
        return jsonDecode(value);
      }
      final secretKey = _secretKey;
      if (secretKey == null) {
        throw StateError(
          'The KMS data in window.localStorage is encrypted, but no secret key was given.',
        );
      }
      final bytes = base64Decode(value);
      final cipherText = bytes.skip(12).toList(growable: false);
      final nonce = Nonce(bytes.take(12).toList(growable: false));
      final clearText = await chacha20Poly1305Aead.decrypt(
        cipherText,
        secretKey: secretKey,
        nonce: nonce,
      );
      return jsonDecode(utf8.decode(clearText));
    } else {
      return null;
    }
  }

  Completer _mutateCompleter;

  Future<void> _mutate(
      FutureOr<Map<String, Object>> Function(Map<String, Object> json)
          callback) async {
    // Prevent concurrent mutations
    while (_mutateCompleter != null) {
      await _mutateCompleter.future;
    }
    _mutateCompleter = Completer();
    try {
      final json = (await _load()) ?? <String, Object>{};
      final namespace = this.namespace ?? 'default';
      final key = 'kms:$namespace';
      var value = jsonEncode(json);

      final secretKey = _secretKey;
      if (secretKey == null) {
        html.window.localStorage[key] = value;
      } else {
        final nonce = chacha20Poly1305Aead.newNonce();
        final cipherText = await chacha20Poly1305Aead.encrypt(
          utf8.encode(value),
          secretKey: secretKey,
          nonce: nonce,
        );
        value = base64Encode(<int>[
          ...nonce.bytes,
          ...cipherText,
        ]);
        html.window.localStorage[key] = value;
      }
    } finally {
      _mutateCompleter.complete();
      _mutateCompleter = null;
    }
  }
}

class BrowserSession {}

class _BrowserKeyCollection extends KeyCollection {
  @override
  final BrowserKmsImpl kms;

  @override
  final String collectionId;

  _BrowserKeyCollection(this.kms, this.collectionId);

  @override
  Future<KeyDocument> createKeyPair({
    KeyExchangeType keyExchangeType,
    SignatureType signatureType,
    KeyDocumentSecurity keyDocumentSecurity,
    String documentId,
  }) async {
    if (keyExchangeType == null && signatureType == null) {
      throw ArgumentError(
        'keyExchangeType or signatureType must be non-null',
      );
    }
    final keyExchangeAlgorithm =
        defaultKeyExchangeImplementations[keyExchangeType];
    final signatureAlgorithm = defaultSignatureImplementations[signatureType];
    if (keyExchangeAlgorithm == null && signatureAlgorithm == null) {
      throw ArgumentError(
        'The algorithm is unsupported',
      );
    }
    if (keyExchangeAlgorithm != null && signatureAlgorithm != null) {
      throw ArgumentError(
        "Key pair can't be used for both key exchange and signature",
      );
    }
    documentId ??= KeyDocument.randomId();

    final documentJson = <String, Object>{};
    KeyPair keyPair;
    if (keyExchangeAlgorithm != null) {
      documentJson['keyExchangeAlgorithmName'] = keyExchangeAlgorithm.name;
      keyPair = await keyExchangeAlgorithm.newKeyPair();
    }
    if (signatureAlgorithm != null) {
      documentJson['signatureAlgorithmName'] = signatureAlgorithm.name;
      keyPair = await keyExchangeAlgorithm.newKeyPair();
    }
    documentJson['privateKey'] = base64Encode(keyPair.privateKey.extractSync());
    documentJson['publicKey'] = base64Encode(keyPair.publicKey.bytes);

    await kms._mutate((kmsJson) async {
      final collectionJson =
          kmsJson.putIfAbsent(collectionId, () => <String, Object>{}) as Map;
      collectionJson[documentId] = documentJson;
      return kmsJson;
    });
    return document(documentId);
  }

  @override
  Future<KeyDocument> createSecretKey({
    CipherType cipherType,
    KeyDocumentSecurity keyDocumentSecurity,
    String documentId,
  }) async {
    final cipher = defaultCipherImplementations[cipherType];
    if (cipher == null) {
      throw ArgumentError.value(cipherType, 'cipherType', 'Unsupported value');
    }
    documentId ??= KeyDocument.randomId();
    final secretKey = await cipher.newSecretKey();
    final documentJson = <String, Object>{
      'cipherName': cipher.name,
      'secretKey': base64Encode(secretKey.extractSync()),
    };
    await kms._mutate((kmsJson) async {
      final collectionJson =
          kmsJson.putIfAbsent(collectionId, () => <String, Object>{}) as Map;
      collectionJson[documentId] = documentJson;
      return kmsJson;
    });
    return document(documentId);
  }

  @override
  KeyDocument document(String documentId) {
    return _BrowserKeyDocument(this, documentId);
  }

  @override
  Stream<KeyDocument> documentsAsStream() async* {
    final json = await kms._load();
    final collectionJson = json[collectionId];
    if (collectionJson is Map) {
      for (var key in collectionJson.keys) {
        yield (document(key));
      }
    }
  }
}

class _BrowserKeyDocument extends KeyDocument {
  @override
  final _BrowserKeyCollection collection;
  @override
  final String documentId;

  _BrowserKeyDocument(this.collection, this.documentId);

  @override
  Future<List<int>> decrypt(
    List<int> message, {
    @required Nonce nonce,
    List<int> aad,
  }) async {
    final json = await _load();
    if (json == null) {
      throw KeyDocumentDoesNotExistException(this);
    }
    final secretKeyJson = json['secretKey'];
    if (secretKeyJson == null) {
      throw StateError('Key does not support encryption/decryption');
    }
    final secretKey = SecretKey(base64Decode(secretKeyJson as String));
    final cipherName = json['cipherName'] as String;
    final cipher = defaultCipherImplementations.values
        .singleWhere((c) => c.name == cipherName);
    return cipher.decrypt(
      message,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
    );
  }

  @override
  Future<void> delete() async {
    await collection.kms._mutate((kmsJson) {
      if (kmsJson is Map) {
        final collectionJson = kmsJson[collection.collectionId];
        if (collectionJson is Map && collectionJson.containsKey(documentId)) {
          collectionJson.remove(documentId);
          if (collectionJson.isEmpty) {
            kmsJson.remove(collection.collectionId);
          }
        }
      }
      return kmsJson;
    });
  }

  @override
  Future<List<int>> encrypt(
    List<int> message, {
    @required Nonce nonce,
    List<int> aad,
  }) async {
    final json = await _load();
    if (json == null) {
      throw KeyDocumentDoesNotExistException(this);
    }
    final secretKeyJson = json['secretKey'];
    if (secretKeyJson == null) {
      throw StateError('Key does not support encryption/decryption');
    }
    final secretKey = SecretKey(base64Decode(secretKeyJson as String));
    final cipherName = json['cipherName'] as String;
    final cipher = defaultCipherImplementations.values
        .singleWhere((c) => c.name == cipherName);
    return cipher.encrypt(
      message,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
    );
  }

  @override
  Future<PublicKey> getPublicKey() async {
    final json = await _load();
    if (json == null) {
      throw KeyDocumentDoesNotExistException(this);
    }
    final publicKeyJson = json['publicKey'];
    if (publicKeyJson == null) {
      throw StateError('Not a key pair');
    }
    return PublicKey(base64Decode(publicKeyJson as String));
  }

  @override
  Future<SecretKey> sharedSecret(
      {PublicKey remotePublicKey, KeyExchangeType keyExchangeType}) async {
    final json = await _load();
    if (json == null) {
      throw KeyDocumentDoesNotExistException(this);
    }
    final algNameOrNull = json['keyExchangeAlgorithmName'];
    if (algNameOrNull == null) {
      throw StateError('Key does not support key exchange');
    }
    final algName = algNameOrNull as String;
    final alg = defaultKeyExchangeImplementations.values
        .singleWhere((c) => c.name == algName);
    final privateKeyBase64 = json['privateKey'] as String;
    final privateKeyBytes = base64Decode(privateKeyBase64);
    final privateKey = PrivateKey(privateKeyBytes);
    return alg.sharedSecret(
      localPrivateKey: privateKey,
      remotePublicKey: remotePublicKey,
    );
  }

  @override
  Future<Signature> sign(List<int> message) async {
    final json = await _load();
    if (json == null) {
      throw KeyDocumentDoesNotExistException(this);
    }
    final algNameOrNull = json['signatureAlgorithmName'];
    if (algNameOrNull == null) {
      throw StateError('Key does not support signing');
    }
    final algName = algNameOrNull as String;
    final alg = defaultSignatureImplementations.values
        .singleWhere((c) => c.name == algName);
    final privateKey = PrivateKey(base64Decode(json['privateKey']));
    final publicKey = PublicKey(base64Decode(json['publicKey']));
    return alg.sign(
      message,
      KeyPair(
        privateKey: privateKey,
        publicKey: publicKey,
      ),
    );
  }

  Future<Map> _load() async {
    final kmsJson = await collection.kms._load();
    final collectionJson = kmsJson[collection.collectionId];
    if (collectionJson is Map) {
      final documentJson = collectionJson[documentId];
      if (documentJson is Map) {
        return documentJson;
      }
    }
    return null;
  }
}
