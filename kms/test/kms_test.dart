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
    test('== / hashCode', () {
      final value = KmsKey(keyRingId: 'a', id: 'b');
      final clone = KmsKey(keyRingId: 'a', id: 'b');
      final other0 = KmsKey(keyRingId: 'OTHER', id: 'b');
      final other1 = KmsKey(keyRingId: 'a', id: 'OTHER');
      expect(value, clone);
      expect(value, isNot(other0));
      expect(value, isNot(other1));
    });

    test('KmsKey.random()', () {
      final key0 = KmsKey.random(keyRingId: 'example');
      final key1 = KmsKey.random(keyRingId: 'example');
      expect(key0, isNot(key1));
      expect(key0.id.length, 32);
      expect(key1.id.length, 32);
      expect(key0.id, matches(RegExp(r'^[0-9a-f]{32}$')));
    });
  });

  group('MemoryKms:', () {
    Kms kms;

    setUp(() {
      kms = MemoryKms();
    });

    group('createKeyPair():', () {
      test('simple case', () async {
        final kmsKey = await kms.createKeyPair(
          keyRingId: 'exampleKeyRingId',
          keyExchangeType: KeyExchangeType.x25519,
          signatureType: null,
        );
        expect(kmsKey.keyRingId, 'exampleKeyRingId');
        expect(kmsKey.id, hasLength(32));
        expect(kmsKey.id, matches(RegExp(r'^[0-9a-f]{32}$')));
      });

      test('with predefined key', () async {
        final kmsKey = await kms.createKeyPair(
          keyRingId: 'exampleKeyRingId',
          keyExchangeType: KeyExchangeType.x25519,
          signatureType: null,
          id: 'exampleId',
        );
        expect(kmsKey.keyRingId, 'exampleKeyRingId');
        expect(kmsKey.id, 'exampleId');
      });

      test('with predefined key, throws StateError if exists', () async {
        final f = () {
          return kms.createKeyPair(
            keyRingId: 'keyRingId',
            keyExchangeType: KeyExchangeType.x25519,
            signatureType: null,
            id: 'id',
          );
        };

        await f();
        await expectLater(
          f(),
          throwsStateError,
        );
      });

      test('with predefined key, throws StateError if deleted', () async {
        final f = () {
          return kms.createKeyPair(
            keyRingId: 'keyRingId',
            keyExchangeType: KeyExchangeType.x25519,
            signatureType: null,
            id: 'id',
          );
        };

        final key = await f();
        await kms.delete(key);
        await expectLater(
          f(),
          throwsStateError,
        );
      });

      test('throws ArgumentError if keyRingId is null', () async {
        await expectLater(
          kms.createKeyPair(
            keyRingId: null,
            keyExchangeType: KeyExchangeType.x25519,
            signatureType: null,
          ),
          throwsArgumentError,
        );
      });

      test('throws ArgumentError if algorithms are all null', () async {
        await expectLater(
          kms.createKeyPair(
            keyRingId: 'example',
            keyExchangeType: null,
            signatureType: null,
          ),
          throwsArgumentError,
        );
      });

      test('throws ArgumentError if algorithms are incompatible', () async {
        await expectLater(
          kms.createKeyPair(
            keyRingId: 'example',
            keyExchangeType: KeyExchangeType.x25519,
            signatureType: SignatureType.p256,
          ),
          throwsArgumentError,
        );
      });
    });

    group('createSecretKey():', () {
      test('simple case', () async {
        final kmsKey = await kms.createSecretKey(
          keyRingId: 'keyRingId',
          cipherType: CipherType.chacha20Poly1305,
        );
        expect(kmsKey.keyRingId, 'keyRingId');
        expect(kmsKey.id, hasLength(32));
        expect(kmsKey.id, matches(RegExp(r'^[0-9a-f]{32}$')));
      });

      test('with predefined key', () async {
        final kmsKey = await kms.createSecretKey(
          keyRingId: 'keyRingId',
          cipherType: CipherType.chacha20Poly1305,
          id: 'id',
        );
        expect(kmsKey.keyRingId, 'keyRingId');
        expect(kmsKey.id, 'id');
      });

      test('with predefined key, throws StateError if exists', () async {
        final f = () async {
          return kms.createSecretKey(
            keyRingId: 'keyRingId',
            cipherType: CipherType.chacha20Poly1305,
            id: 'id',
          );
        };

        await f();
        await expectLater(
          f(),
          throwsStateError,
        );
      });

      test('with predefined key, throws StateError if deleted', () async {
        final f = () async {
          return kms.createSecretKey(
            keyRingId: 'keyRingId',
            cipherType: CipherType.chacha20Poly1305,
            id: 'id',
          );
        };

        final key = await f();
        await kms.delete(key);
        await expectLater(
          f(),
          throwsStateError,
        );
      });

      test('throws ArgumentError if keyRingId is null', () async {
        await expectLater(
          kms.createSecretKey(
            keyRingId: null,
            cipherType: CipherType.chacha20Poly1305,
          ),
          throwsArgumentError,
        );
      });

      test('throws ArgumentError if algorithm is null', () async {
        await expectLater(
          kms.createSecretKey(
            keyRingId: 'example',
            cipherType: null,
          ),
          throwsArgumentError,
        );
      });
    });

    group('findAll():', () {
      test('no keys', () async {
        final list = await kms.findAll().toList();
        expect(list, isEmpty);
      });

      test('two keys', () async {
        final key0 = await kms.createKeyPair(
          keyRingId: 'example',
          keyExchangeType: KeyExchangeType.x25519,
          signatureType: null,
        );
        final key1 = await kms.createSecretKey(
          keyRingId: 'example',
          cipherType: CipherType.chacha20Poly1305,
        );
        final list = await kms.findAll().toList();
        expect(list, unorderedEquals([key0, key1]));
      });

      test('two keys, one deleted', () async {
        final key0 = await kms.createSecretKey(
          keyRingId: 'example',
          cipherType: CipherType.chacha20Poly1305,
        );
        final key1 = await kms.createSecretKey(
          keyRingId: 'example',
          cipherType: CipherType.chacha20Poly1305,
        );
        await kms.delete(key0);
        final list = await kms.findAll().toList();
        expect(list, [key1]);
      });
    });

    group('delete():', () {
      test('succeeds for key pairs', () async {
        final kmsKey = await kms.createKeyPair(
          keyRingId: 'example',
          keyExchangeType: KeyExchangeType.x25519,
          signatureType: null,
        );
        await expectLater(kms.getPublicKey(kmsKey), isNotNull);
        await kms.delete(kmsKey);
        await expectLater(
          kms.getPublicKey(kmsKey),
          throwsA(isA<KmsKeyDoesNotExistException>()),
        );
      });

      test('succeeds for secret keys', () async {
        final kmsKey = await kms.createSecretKey(
          keyRingId: 'example',
          cipherType: CipherType.chacha20Poly1305,
        );
        final nonce = Nonce.randomBytes(12);
        await expectLater(
          kms.encrypt(
            [1, 2, 3],
            kmsKey: kmsKey,
            nonce: nonce,
            cipherType: CipherType.chacha20Poly1305,
          ),
          isNotNull,
        );
        await kms.delete(kmsKey);
        await expectLater(
          kms.getPublicKey(kmsKey),
          throwsA(isA<KmsKeyDoesNotExistException>()),
        );
      });

      test('succeeds even if key doesn\'t exist', () async {
        await kms.delete(KmsKey(keyRingId: 'a', id: 'b'));
      });
    });

    group('key exchange algorithms:', () {
      test('x25519', () async {
        //
        // Create two key pairs
        //
        final kmsKey0 = await kms.createKeyPair(
          keyRingId: 'example',
          keyExchangeType: KeyExchangeType.x25519,
          signatureType: null,
        );
        expect(kmsKey0, isNotNull);

        final kmsKey1 = await kms.createKeyPair(
          keyRingId: 'example',
          keyExchangeType: KeyExchangeType.x25519,
          signatureType: null,
        );
        expect(kmsKey1, isNotNull);

        //
        // Get public keys
        //

        final publicKey0 = await kms.getPublicKey(kmsKey0);
        expect(publicKey0.bytes, hasLength(32));

        final publicKey1 = await kms.getPublicKey(kmsKey1);
        expect(publicKey1, isNot(publicKey0));
        expect(publicKey1.bytes, hasLength(32));

        //
        // Generate shared secrets
        //
        final sharedSecret0 = await kms.sharedSecret(
          kmsKey: kmsKey0,
          remotePublicKey: publicKey1,
          keyExchangeType: KeyExchangeType.x25519,
        );
        final sharedSecret1 = await kms.sharedSecret(
          kmsKey: kmsKey1,
          remotePublicKey: publicKey0,
          keyExchangeType: KeyExchangeType.x25519,
        );
        expect(sharedSecret0.extractSync(), hasLength(32));
        expect(sharedSecret0, sharedSecret1);

        //
        // Delete the two key pairs
        //
        await kms.delete(kmsKey0);
        await kms.delete(kmsKey1);

        // Using the key should fail
        await expectLater(
          kms.sharedSecret(
            kmsKey: kmsKey0,
            remotePublicKey: publicKey1,
            keyExchangeType: KeyExchangeType.x25519,
          ),
          throwsA(isA<KmsKeyDoesNotExistException>()),
        );
      });
    });

    group('signature algorithms:', () {
      test('ed25519', () async {
        //
        // Create a key pair
        //
        final kmsKey = await kms.createKeyPair(
          keyRingId: 'example',
          keyExchangeType: null,
          signatureType: SignatureType.ed25519,
        );
        expect(kmsKey, isNotNull);

        //
        // Get public key
        //

        final publicKey = await kms.getPublicKey(kmsKey);
        expect(publicKey.bytes, hasLength(32));

        //
        // Sign
        //

        final data = [1, 2, 3];
        final signature = await kms.sign(
          data,
          kmsKey: kmsKey,
          signatureType: SignatureType.ed25519,
        );
        expect(signature.bytes, hasLength(64));
        expect(signature.publicKey, publicKey);

        //
        // Verify signature
        //

        expect(
          await kms.verifySignature(
            data,
            signature: signature,
            kmsKey: kmsKey,
            signatureType: SignatureType.ed25519,
          ),
          isTrue,
        );
        expect(
          await kms.verifySignature(
            [99, 99, 99],
            signature: signature,
            kmsKey: kmsKey,
            signatureType: SignatureType.ed25519,
          ),
          isFalse,
        );

        //
        // Delete the key pair
        //
        await kms.delete(kmsKey);

        // Using the key should fail
        await expectLater(
          kms.verifySignature(
            [1, 2, 3],
            signature: signature,
            kmsKey: kmsKey,
            signatureType: SignatureType.ed25519,
          ),
          throwsA(isA<KmsKeyDoesNotExistException>()),
        );
      });
    });

    group('ciphers:', () {
      test('chacha20Poly1305', () async {
        //
        // Create key
        //

        final kmsKey = await kms.createSecretKey(
          keyRingId: 'example',
          cipherType: CipherType.chacha20Poly1305,
        );
        expect(kmsKey, isNotNull);

        //
        // Encrypt
        //

        final data = [1, 2, 3];
        final nonce = Nonce.randomBytes(12);
        final encrypted = await kms.encrypt(
          data,
          kmsKey: kmsKey,
          nonce: nonce,
          cipherType: CipherType.chacha20Poly1305,
        );
        expect(encrypted, hasLength(3 + 16));
        expect(encrypted, isNot(data));

        //
        // Decrypt
        //

        final decrypted = await kms.decrypt(
          encrypted,
          kmsKey: kmsKey,
          nonce: nonce,
          cipherType: CipherType.chacha20Poly1305,
        );
        expect(decrypted, data);

        //
        // Delete key
        //

        await kms.delete(kmsKey);

        // Using the key should fail
        await expectLater(
          () => kms.encrypt(
            [1, 2, 3],
            kmsKey: kmsKey,
            nonce: nonce,
            cipherType: CipherType.chacha20Poly1305,
          ),
          throwsA(isA<KmsKeyDoesNotExistException>()),
        );
      });
    });
  });
}
