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
import 'package:test/test.dart';

void main() {
  group('KmsKey:', () {
    final Kms kms = MemoryKms();

    test('== / hashCode', () {
      final value = kms.collection('c').document('d');
      final clone = kms.collection('c').document('d');
      final other0 = kms.collection('c').document('other');
      final other1 = kms.collection('other').document('d');
      expect(value, clone);
      expect(value, isNot(other0));
      expect(value, isNot(other1));

      expect(value.hashCode, clone.hashCode);
      expect(value.hashCode, isNot(other0.hashCode));
      expect(value.hashCode, isNot(other1.hashCode));
    });
  });

  test('BrowserKms (VM):', () {
    expect(BrowserKms.get(), isNull);
  }, testOn: 'vm');

  group('BrowserKms (Chrome):', () {
    _testKms(() => BrowserKms.get());
  }, testOn: 'chrome');

  group('MemoryKms:', () {
    _testKms(() => MemoryKms());
  });
}

void _testKms(Kms Function() newKms) {
  Kms kms;
  KeyCollection collection;

  setUp(() {
    kms = newKms();
    collection = kms.collection('example_collection');
  });

  group('collection:', () {
    test('createKeyPair():simple case', () async {
      final key = await kms.collection('default').createKeyPair(
            keyExchangeType: KeyExchangeType.x25519,
            signatureType: null,
          );
      expect(key.collection.kms, kms);
      expect(key.collection.collectionId, 'default');
      expect(key.documentId, hasLength(32));
      expect(key.documentId, matches(RegExp(r'^[0-9a-f]{32}$')));
    });

    test('createKeyPair():with fixed documentId', () async {
      final document = await collection.createKeyPair(
        keyExchangeType: KeyExchangeType.x25519,
        signatureType: null,
        documentId: 'exampleId',
      );
      expect(document.collection, same(collection));
      expect(document.documentId, 'exampleId');
    });

    test('createKeyPair():with fixed documentId, throws StateError if exists',
        () async {
      final f = () {
        return collection.createKeyPair(
          keyExchangeType: KeyExchangeType.x25519,
          signatureType: null,
          documentId: 'id',
        );
      };

      await f();
      await expectLater(
        f(),
        throwsStateError,
      );
    });

    test('createKeyPair():throws ArgumentError if algorithms are all null',
        () async {
      await expectLater(
        collection.createKeyPair(
          keyExchangeType: null,
          signatureType: null,
        ),
        throwsArgumentError,
      );
    });

    test('createKeyPair(): throws ArgumentError if algorithms are incompatible',
        () async {
      await expectLater(
        collection.createKeyPair(
          keyExchangeType: KeyExchangeType.x25519,
          signatureType: SignatureType.ecdsaP256sha256,
        ),
        throwsArgumentError,
      );
    });
  });

  group('createSecretKey():', () {
    test('createSecretKey(): simple case', () async {
      final document = await collection.createSecretKey(
        cipherType: CipherType.chacha20Poly1305Aead,
      );
      expect(document.collection, same(collection));
      expect(document.documentId, hasLength(32));
      expect(document.documentId, matches(RegExp(r'^[0-9a-f]{32}$')));
    });

    test('createSecretKey(): with fixed key', () async {
      final document = await collection.createSecretKey(
        cipherType: CipherType.chacha20Poly1305Aead,
        documentId: 'id',
      );
      expect(document.collection, same(collection));
      expect(document.documentId, 'id');
    });

    test('createSecretKey(): with fixed key, throws StateError if exists',
        () async {
      final f = () async {
        return collection.createSecretKey(
          cipherType: CipherType.chacha20Poly1305Aead,
          documentId: 'id',
        );
      };

      await f();
      await expectLater(
        f(),
        throwsStateError,
      );
    });

    test('createSecretKey(): throws ArgumentError if algorithm is null',
        () async {
      await expectLater(
        collection.createSecretKey(
          cipherType: null,
        ),
        throwsArgumentError,
      );
    });
  });

  group('document:', () {
    KeyDocument document;
    setUp(() async {
      document = await collection.createKeyPair(
        keyExchangeType: KeyExchangeType.x25519,
        signatureType: null,
      );
      addTearDown(() {
        document.delete();
      });
    });

    test('delete() succeeds for key pairs', () async {
      final document = await collection.createKeyPair(
        keyExchangeType: KeyExchangeType.x25519,
        signatureType: null,
      );
      await expectLater(document.getPublicKey(), isNotNull);
      await document.delete();
      await expectLater(
        document.getPublicKey(),
        throwsA(isA<KeyDocumentDoesNotExistException>()),
      );
    });

    test('delete() succeeds for secret keys', () async {
      final document = await collection.createSecretKey(
        cipherType: CipherType.chacha20Poly1305Aead,
      );
      await expectLater(
        document.encrypt([1, 2, 3], nonce: Nonce.randomBytes(12)),
        isNotNull,
      );
      await document.delete();
      await expectLater(
        document.encrypt([1, 2, 3], nonce: Nonce.randomBytes(12)),
        throwsA(isA<KeyDocumentDoesNotExistException>()),
      );
    });

    test('x25519', () async {
      //
      // Create two key pairs
      //
      final document = await collection.createKeyPair(
        keyExchangeType: KeyExchangeType.x25519,
        signatureType: null,
      );
      expect(document, isNotNull);

      final otherDocument = await collection.createKeyPair(
        keyExchangeType: KeyExchangeType.x25519,
        signatureType: null,
      );
      expect(otherDocument, isNotNull);

      //
      // Get public keys
      //

      final publicKey = await document.getPublicKey();
      expect(publicKey.bytes, hasLength(32));

      final otherPublicKey = await otherDocument.getPublicKey();
      expect(otherPublicKey, isNot(publicKey));
      expect(otherPublicKey.bytes, hasLength(32));

      //
      // Generate shared secrets
      //
      final sharedSecret = await document.sharedSecret(
        remotePublicKey: otherPublicKey,
      );
      final otherSharedSecret = await otherDocument.sharedSecret(
        remotePublicKey: publicKey,
      );
      expect(sharedSecret.extractSync(), hasLength(32));
      expect(sharedSecret, otherSharedSecret);

      //
      // Delete the two key pairs
      //
      await document.delete();
      await otherDocument.delete();

      // Using the key should fail
      await expectLater(
        document.sharedSecret(
          remotePublicKey: otherPublicKey,
        ),
        throwsA(isA<KeyDocumentDoesNotExistException>()),
      );
    });

    test('ed25519', () async {
      //
      // Create a key pair
      //
      final document = await collection.createKeyPair(
        keyExchangeType: null,
        signatureType: SignatureType.ed25519,
      );
      expect(document, isNotNull);

      //
      // Get the public key
      //

      final publicKey = await document.getPublicKey();
      expect(publicKey.bytes, hasLength(32));

      //
      // Sign
      //

      final data = [1, 2, 3];
      final signature = await document.sign(
        data,
      );
      expect(signature.bytes, hasLength(64));
      expect(signature.publicKey, publicKey);

      //
      // Delete the key pair
      //
      await document.delete();
    });

    test('chacha20Poly1305', () async {
      //
      // Create a key
      //

      final document = await collection.createSecretKey(
        cipherType: CipherType.chacha20Poly1305Aead,
      );
      expect(document, isNotNull);

      //
      // Encrypt
      //

      final data = [1, 2, 3];
      final nonce = Nonce.randomBytes(12);
      final encrypted = await document.encrypt(
        data,
        nonce: nonce,
      );
      expect(encrypted, hasLength(3 + 16));
      expect(encrypted, isNot(data));

      //
      // Decrypt
      //

      final decrypted = await document.decrypt(
        encrypted,
        nonce: nonce,
      );
      expect(decrypted, data);

      //
      // Delete key
      //

      await document.delete();

      // Using the key should fail
      await expectLater(
        () => document.encrypt(
          [1, 2, 3],
          nonce: nonce,
        ),
        throwsA(isA<KeyDocumentDoesNotExistException>()),
      );
    });
  });
}
