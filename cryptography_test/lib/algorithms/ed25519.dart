// Copyright 2023 Gohilla.
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

import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:test/expect.dart';
import 'package:test/scaffolding.dart';

import '../hex.dart';
import '../signature.dart';

void testEd25519() {
  testSignatureAlgorithm(
    builder: () => Ed25519(),
    otherTests: () {
      _test();
    },
  );
}

void _test() {
  group('ed25519:', () {
    late Ed25519 algorithm;

    setUp(() {
      algorithm = Ed25519();
    });

    test('information', () {
      expect(algorithm.keyPairType, same(KeyPairType.ed25519));
      expect(algorithm.keyPairType.name, 'ed25519');
      expect(algorithm.keyPairType.publicKeyLength, 32);
    });

    test('generate 100 random keyPairs, sign/verify a random message',
        () async {
      for (var i = 0; i < 100; i++) {
        // Generate a random key pair
        final keyPair = await algorithm.newKeyPair();
        final publicKey = await keyPair.extractPublicKey();
        expect(publicKey.bytes, hasLength(32));

        // Generate a random message
        final message = List<int>.filled(1 + (i % 128), 0);

        // sign()
        final signature = await algorithm.sign(
          message,
          keyPair: keyPair,
        );
        expect(signature.publicKey, publicKey, reason: 'iteration = $i');

        // Verify the signed message.
        expect(
          await algorithm.verify(message, signature: signature),
          isTrue,
        );

        // Try verify a slightly different message, the same signature.
        final otherMessage = <int>[
          // Change first byte of message
          (message[0] + 1) % 256,
          ...message.skip(1),
        ];
        expect(
          await algorithm.verify(
            otherMessage,
            signature: signature,
          ),
          isFalse,
        );

        // Try verify the same message, slightly different signature.
        final otherSignature = Signature(
          <int>[
            // Change first byte of signature bytes
            (signature.bytes[0] + 1) % 256,
            ...signature.bytes.skip(1),
          ],
          publicKey: publicKey,
        );
        expect(
          await algorithm.verify(
            message,
            signature: otherSignature,
          ),
          isFalse,
        );
      }
    });
    group('Test vectors from RFC 8032:', () {
      group('test vector #1:', () {
        // The following constants are test vectors from RFC 8032:
        // https://tools.ietf.org/html/rfc8032

        late List<int> message;
        late List<int> privateKeyBytes;
        late List<int> publicKeyBytes;
        late List<int> signatureBytes;
        late Signature signature;

        setUp(() {
          message = const <int>[];
          privateKeyBytes = hexToBytes(
            '9d61b19deffd5a60ba844af492ec2cc4'
            '4449c5697b326919703bac031cae7f60',
          );
          publicKeyBytes = hexToBytes(
            'd75a980182b10ab7d54bfed3c964073a'
            '0ee172f3daa62325af021a68f707511a',
          );
          signatureBytes = hexToBytes(
            'e5564300c360ac729086e2cc806e828a'
            '84877f1eb8e5d974d873e06522490155'
            '5fb8821590a33bacc61e39701cf9b46b'
            'd25bf5f0595bbe24655141438e7a100b',
          );
          signature = Signature(
            signatureBytes,
            publicKey: SimplePublicKey(
              publicKeyBytes,
              type: KeyPairType.ed25519,
            ),
          );
        });

        test('sign(...)', () async {
          final keyPair = await algorithm.newKeyPairFromSeed(privateKeyBytes);
          final actualSignature = await algorithm.sign(
            message,
            keyPair: keyPair,
          );
          expect(
            hexFromBytes(actualSignature.bytes),
            hexFromBytes(signatureBytes),
          );
          expect(
            actualSignature.publicKey,
            SimplePublicKey(publicKeyBytes, type: algorithm.keyPairType),
          );
          expect(
            actualSignature.publicKey,
            await keyPair.extractPublicKey(),
          );
          expect(actualSignature, signature);
        });

        test('verify(...)', () async {
          final isOk = await algorithm.verify(
            message,
            signature: signature,
          );
          expect(isOk, isTrue);
        });

        test('verifying fails when we use other message', () async {
          final isOk = await algorithm.verify(
            [1, 2, 3],
            signature: signature,
          );
          expect(isOk, isFalse);
        });

        test('verifying fails when we use other signature bytes', () async {
          // A real signature (example #2)
          final otherBytes = hexToBytes(
            '92a009a9f0d4cab8720e820b5f642540'
            'a2b27b5416503f8fb3762223ebdb69da'
            '085ac1e43e15996e458f3613d0f11d8c'
            '387b2eaeb4302aeeb00d291612bb0c00',
          );
          final isOk = await algorithm.verify(
            message,
            signature: Signature(
              otherBytes,
              publicKey: signature.publicKey,
            ),
          );
          expect(isOk, isFalse);
        });

        test('verifying fails when we use other public key', () async {
          // A real public key (example #2)
          final otherPublicKey = SimplePublicKey(
            hexToBytes(
              '3d4017c3e843895a92b70aa74d1b7ebc'
              '9c982ccf2ec4968cc0cd55f12af4660c',
            ),
            type: algorithm.keyPairType,
          );
          final isOk = await algorithm.verify(
            message,
            signature: Signature(
              signature.bytes,
              publicKey: otherPublicKey,
            ),
          );
          expect(isOk, isFalse);
        });
      });

      group('test vector #2', () {
        // The following constants are test vectors from RFC 8032:
        // https://tools.ietf.org/html/rfc8032

        late List<int> message;
        late List<int> privateKeyBytes;
        late List<int> publicKeyBytes;
        late List<int> signatureBytes;
        late Signature signature;

        setUp(() {
          message = hexToBytes(
            '72',
          );
          privateKeyBytes = hexToBytes(
            '4ccd089b28ff96da9db6c346ec114e0f'
            '5b8a319f35aba624da8cf6ed4fb8a6fb',
          );
          publicKeyBytes = hexToBytes(
            '3d4017c3e843895a92b70aa74d1b7ebc'
            '9c982ccf2ec4968cc0cd55f12af4660c',
          );
          signatureBytes = hexToBytes(
            '92a009a9f0d4cab8720e820b5f642540'
            'a2b27b5416503f8fb3762223ebdb69da'
            '085ac1e43e15996e458f3613d0f11d8c'
            '387b2eaeb4302aeeb00d291612bb0c00',
          );
          signature = Signature(
            signatureBytes,
            publicKey: SimplePublicKey(
              publicKeyBytes,
              type: KeyPairType.ed25519,
            ),
          );
        });

        test('sign(...)', () async {
          final keyPair = await algorithm.newKeyPairFromSeed(privateKeyBytes);
          final actualSignature = await algorithm.sign(
            message,
            keyPair: keyPair,
          );
          expect(
            hexFromBytes(actualSignature.bytes),
            hexFromBytes(signature.bytes),
          );
          expect(
            actualSignature.publicKey,
            SimplePublicKey(publicKeyBytes, type: algorithm.keyPairType),
          );
          expect(
            actualSignature.publicKey,
            await keyPair.extractPublicKey(),
          );
          expect(actualSignature, signature);
        });

        test('verify(...)', () async {
          final isOk = await algorithm.verify(
            message,
            signature: signature,
          );
          expect(
            isOk,
            isTrue,
          );
        });
      });

      group('test vector #3', () {
        // The following constants are test vectors from RFC 8032:
        // https://tools.ietf.org/html/rfc8032

        late List<int> message;
        late List<int> privateKeyBytes;
        late List<int> publicKeyBytes;
        late List<int> signatureBytes;
        late Signature signature;

        setUp(() {
          message = hexToBytes(
            'af82',
          );
          privateKeyBytes = hexToBytes(
            'c5aa8df43f9f837bedb7442f31dcb7b1'
            '66d38535076f094b85ce3a2e0b4458f7',
          );
          publicKeyBytes = hexToBytes(
            'fc51cd8e6218a1a38da47ed00230f058'
            '0816ed13ba3303ac5deb911548908025',
          );
          signatureBytes = hexToBytes(
            '6291d657deec24024827e69c3abe01a3'
            '0ce548a284743a445e3680d7db5ac3ac'
            '18ff9b538d16f290ae67f760984dc659'
            '4a7c15e9716ed28dc027beceea1ec40a',
          );
          signature = Signature(
            signatureBytes,
            publicKey: SimplePublicKey(
              publicKeyBytes,
              type: KeyPairType.ed25519,
            ),
          );
        });

        test('sign()', () async {
          final keyPair = await algorithm.newKeyPairFromSeed(privateKeyBytes);
          final actualSignature = await algorithm.sign(
            message,
            keyPair: keyPair,
          );
          expect(
            hexFromBytes(actualSignature.bytes),
            hexFromBytes(signature.bytes),
          );
          expect(
            actualSignature.publicKey,
            SimplePublicKey(publicKeyBytes, type: algorithm.keyPairType),
          );
          expect(
            actualSignature.publicKey,
            await keyPair.extractPublicKey(),
          );
          expect(actualSignature, signature);
        });

        test('verify(...)', () async {
          final isOk = await algorithm.verify(
            message,
            signature: signature,
          );
          expect(
            isOk,
            isTrue,
          );
        });
      });
    });
  });
}
