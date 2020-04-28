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

import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart' as impl;
import 'package:kms/kms.dart';

class _PluginKeyCollection extends KeyCollection {
  @override
  final PluginKms kms;

  @override
  final String collectionId;

  _PluginKeyCollection(this.kms, this.collectionId);

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
    final json = <String, Object>{};
    KeyPair keyPair;
    if (keyExchangeAlgorithm != null) {
      json['keyExchangeAlg'] = keyExchangeAlgorithm.name;
      keyPair = await keyExchangeAlgorithm.newKeyPair();
    }
    if (signatureAlgorithm != null) {
      json['signatureAlg'] = signatureAlgorithm.name;
      keyPair = await signatureAlgorithm.newKeyPair();
    }
    json['privateKey'] = base64Encode(keyPair.privateKey.extractSync());
    json['publicKey'] = base64Encode(keyPair.publicKey.bytes);

    final key = '$collectionId${PluginKms.keySeparator}$documentId';
    final value = jsonEncode(json);
    await kms._impl.write(key: key, value: value);
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
    final json = <String, Object>{
      'cipherAlg': cipher.name,
      'secretKey': base64Encode(secretKey.extractSync()),
    };

    final key = '$collectionId${PluginKms.keySeparator}$documentId';
    final value = jsonEncode(json);
    await kms._impl.write(key: key, value: value);
    return document(documentId);
  }

  @override
  KeyDocument document(String documentId) {
    return _PluginKeyDocument(this, documentId);
  }

  @override
  Stream<KeyDocument> documentsAsStream() async* {
    final all = await kms._impl.readAll();
    for (var key in all.keys) {
      final i = key.indexOf(PluginKms.keySeparator);
      if (i < 0) {
        continue;
      }
      final collectionId = key.substring(0, i);
      if (collectionId != this.collectionId) {
        continue;
      }
      yield (document(key.substring(i + PluginKms.keySeparator.length)));
    }
  }
}

class _PluginKeyDocument extends KeyDocument {
  @override
  final _PluginKeyCollection collection;

  @override
  final String documentId;

  _PluginKeyDocument(this.collection, this.documentId);

  String get _key =>
      '${collection.collectionId}${PluginKms.keySeparator}$documentId';

  Future<Map<String, Object>> _readJson() async {
    final value = await collection.kms._impl.read(key: _key);
    return json.decode(value);
  }

  @override
  Future<List<int>> decrypt(List<int> message,
      {Nonce nonce, List<int> aad}) async {
    final json = await _readJson();
    final algName = json['cipherAlg'] as String;
    final alg = defaultCipherImplementations.values
        .singleWhere((c) => c.name == algName);
    final secretKeyBase64 = json['secretKey'] as String;
    final secretKey = SecretKey(base64.decode(secretKeyBase64));
    return alg.decrypt(
      message,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
    );
  }

  @override
  Future<void> delete() async {
    await collection.kms._impl.delete(key: _key);
  }

  @override
  Future<List<int>> encrypt(List<int> message,
      {Nonce nonce, List<int> aad}) async {
    final json = await _readJson();
    final algName = json['cipherAlg'] as String;
    final alg = defaultCipherImplementations.values
        .singleWhere((c) => c.name == algName);
    final secretKeyBase64 = json['secretKey'] as String;
    final secretKey = SecretKey(base64.decode(secretKeyBase64));
    return alg.encrypt(
      message,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
    );
  }

  @override
  Future<PublicKey> getPublicKey() async {
    final json = await _readJson();
    if (json['publicKey'] == null) {
      return null;
    }
    final publicKeyBase64 = json['publicKey'] as String;
    return PublicKey(base64.decode(publicKeyBase64));
  }

  @override
  Future<SecretKey> sharedSecret({PublicKey remotePublicKey}) async {
    final json = await _readJson();
    final algName = json['keyExchangeAlg'] as String;
    final alg = defaultKeyExchangeImplementations.values
        .singleWhere((c) => c.name == algName);
    final privateKeyBase64 = json['privateKey'] as String;
    final privateKey = PrivateKey(base64.decode(privateKeyBase64));
    return alg.sharedSecret(
      localPrivateKey: privateKey,
      remotePublicKey: remotePublicKey,
    );
  }

  @override
  Future<Signature> sign(List<int> message) async {
    final json = await _readJson();
    final algName = json['signatureAlg'] as String;
    final alg = defaultSignatureImplementations.values
        .singleWhere((c) => c.name == algName);
    final privateKeyBase64 = json['privateKey'] as String;
    final privateKey = PrivateKey(base64.decode(privateKeyBase64));
    final publicKeyBase64 = json['publicKey'] as String;
    final publicKey = PublicKey(base64.decode(publicKeyBase64));
    final keyPair = KeyPair(privateKey: privateKey, publicKey: publicKey);
    return alg.sign(
      message,
      keyPair,
    );
  }
}

class PluginKms extends Kms {
  static const String keySeparator = '/';
  final impl.FlutterSecureStorage _impl = impl.FlutterSecureStorage();

  @override
  Set<CipherType> get supportedCipherTypes => throw UnimplementedError();

  @override
  Set<KeyExchangeType> get supportedKeyExchangeTypes =>
      throw UnimplementedError();

  @override
  Set<SignatureType> get supportedSignatureTypes => throw UnimplementedError();

  @override
  KeyCollection collection(String collectionId) {
    return _PluginKeyCollection(this, collectionId);
  }

  @override
  Stream<KeyCollection> collectionsAsStream() {
    final collectionIds = <String>{};
    return documentsAsStream()
        .map((document) => document.collection)
        .where((collection) => collectionIds.add(collection.collectionId));
  }

  @override
  Stream<KeyDocument> documentsAsStream() async* {
    final all = await _impl.readAll();
    final collections = <String, KeyCollection>{};
    for (var key in all.keys) {
      final i = key.indexOf(keySeparator);
      if (i < 0) {
        continue;
      }
      final collectionId = key.substring(0, i);
      final documentId = key.substring(i + keySeparator.length);
      final collection = collections.putIfAbsent(
          collectionId, () => this.collection(collectionId));
      final document = collection.document(documentId);
      yield (document);
    }
  }
}
