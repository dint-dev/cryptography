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
import 'package:cryptography/src/utils.dart';
import 'package:test/test.dart';

void main() {
  group('ed25519:', () {
    test('generate 100 random keyPairs, sign/verify a random message',
        () async {
      for (var i = 0; i < 100; i++) {
        // Generate a random key pair
        final keyPair = ed25519.newKeyPairSync();
        expect(keyPair.publicKey.bytes.length, 32);

        // Generate a random message
        final message = Nonce.randomBytes(1 + (i % 128)).bytes;

        // sign()
        final signature = await ed25519.sign(
          message,
          keyPair,
        );
        expect(signature.publicKey, keyPair.publicKey);

        // signSync()
        expect(
          ed25519.signSync(
            message,
            keyPair,
          ),
          signature,
        );

        // Verify the signed message.
        expect(
          await ed25519.verify(message, signature),
          isTrue,
        );
        expect(
          ed25519.verifySync(message, signature),
          isTrue,
        );

        // Try verify a slightly different message, the same signature.
        final otherMessage = <int>[
          // Change first byte of message
          (message[0] + 1) % 256,
          ...message.skip(1),
        ];
        expect(
          await ed25519.verify(
            otherMessage,
            signature,
          ),
          isFalse,
        );
        expect(
          ed25519.verifySync(
            otherMessage,
            signature,
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
          publicKey: keyPair.publicKey,
        );

        expect(
          await ed25519.verify(
            message,
            otherSignature,
          ),
          isFalse,
        );
        expect(
          ed25519.verifySync(
            message,
            otherSignature,
          ),
          isFalse,
        );
      }
    });
    group('Test vectors from RFC 8032:', () {
      group('test vector #1:', () {
        // The following constants are test vectors from RFC 8032:
        // https://tools.ietf.org/html/rfc8032

        final privateKey = PrivateKey(hexToBytes(
          '9d61b19deffd5a60ba844af492ec2cc4'
          '4449c5697b326919703bac031cae7f60',
        ));
        final publicKey = PublicKey(hexToBytes(
          'd75a980182b10ab7d54bfed3c964073a'
          '0ee172f3daa62325af021a68f707511a',
        ));
        final message = const <int>[];
        final signatureBytes = hexToBytes(
          'e5564300c360ac729086e2cc806e828a'
          '84877f1eb8e5d974d873e06522490155'
          '5fb8821590a33bacc61e39701cf9b46b'
          'd25bf5f0595bbe24655141438e7a100b',
        );

        final keyPair = KeyPair(
          privateKey: privateKey,
          publicKey: publicKey,
        );

        final signature = Signature(
          signatureBytes,
          publicKey: publicKey,
        );

        test('sign(...)', () async {
          final actualSignature = await ed25519.sign(
            message,
            keyPair,
          );
          expect(
            hexFromBytes(actualSignature.bytes),
            hexFromBytes(signature.bytes),
          );
          expect(
            actualSignature.publicKey.bytes,
            publicKey.bytes,
          );
        });

        test('signSync(...)', () {
          final actualSignature = ed25519.signSync(
            message,
            keyPair,
          );
          expect(
            hexFromBytes(actualSignature.bytes),
            hexFromBytes(signature.bytes),
          );
          expect(
            actualSignature.publicKey.bytes,
            publicKey.bytes,
          );
        });

        test('verify(...)', () async {
          final isOk = ed25519.verifySync(
            message,
            signature,
          );
          expect(
            isOk,
            isTrue,
          );
        });

        test('verifySync(...)', () {
          final isOk = ed25519.verifySync(
            message,
            signature,
          );
          expect(
            isOk,
            isTrue,
          );
        });

        test('verifying fails when we use other message', () {
          expect(
            ed25519.verifySync(
              [1, 2, 3],
              signature,
            ),
            isFalse,
          );
        });

        test('verifying fails when we use other signature bytes', () {
          expect(
            ed25519.verifySync(
              message,
              Signature(
                // From example #2
                hexToBytes(
                  '92a009a9f0d4cab8720e820b5f642540'
                  'a2b27b5416503f8fb3762223ebdb69da'
                  '085ac1e43e15996e458f3613d0f11d8c'
                  '387b2eaeb4302aeeb00d291612bb0c00',
                ),
                publicKey: signature.publicKey,
              ),
            ),
            isFalse,
          );
        });

        test('verifying fails when we use other public key', () {
          expect(
            ed25519.verifySync(
              message,
              Signature(
                signature.bytes,
                publicKey: PublicKey(hexToBytes(
                  // From example #2
                  '3d4017c3e843895a92b70aa74d1b7ebc'
                  '9c982ccf2ec4968cc0cd55f12af4660c',
                )),
              ),
            ),
            isFalse,
          );
        });
      });

      group('test vector #2', () {
        // The following constants are test vectors from RFC 8032:
        // https://tools.ietf.org/html/rfc8032

        final privateKey = PrivateKey(hexToBytes(
          '4ccd089b28ff96da9db6c346ec114e0f'
          '5b8a319f35aba624da8cf6ed4fb8a6fb',
        ));

        final publicKey = PublicKey(hexToBytes(
          '3d4017c3e843895a92b70aa74d1b7ebc'
          '9c982ccf2ec4968cc0cd55f12af4660c',
        ));

        final message = const <int>[0x72];

        final signatureBytes = hexToBytes(
          '92a009a9f0d4cab8720e820b5f642540'
          'a2b27b5416503f8fb3762223ebdb69da'
          '085ac1e43e15996e458f3613d0f11d8c'
          '387b2eaeb4302aeeb00d291612bb0c00',
        );

        final keyPair = KeyPair(
          privateKey: privateKey,
          publicKey: publicKey,
        );

        final signature = Signature(
          signatureBytes,
          publicKey: publicKey,
        );

        test('sign(...)', () async {
          final actualSignature = await ed25519.sign(
            message,
            keyPair,
          );
          expect(
            hexFromBytes(actualSignature.bytes),
            hexFromBytes(signature.bytes),
          );
          expect(
            actualSignature.publicKey.bytes,
            keyPair.publicKey.bytes,
          );
        });

        test('signSync(...)', () {
          final actualSignature = ed25519.signSync(
            message,
            keyPair,
          );
          expect(
            hexFromBytes(actualSignature.bytes),
            hexFromBytes(signature.bytes),
          );
          expect(
            actualSignature.publicKey.bytes,
            keyPair.publicKey.bytes,
          );
        });

        test('verify(...)', () async {
          final isOk = await ed25519.verify(
            message,
            signature,
          );
          expect(
            isOk,
            isTrue,
          );
        });

        test('verifySync(...)', () {
          final isOk = ed25519.verifySync(
            message,
            signature,
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

        final privateKey = PrivateKey(hexToBytes(
          'c5aa8df43f9f837bedb7442f31dcb7b1'
          '66d38535076f094b85ce3a2e0b4458f7',
        ));

        final publicKey = PublicKey(hexToBytes(
          'fc51cd8e6218a1a38da47ed00230f058'
          '0816ed13ba3303ac5deb911548908025',
        ));

        final message = const <int>[0xaf, 0x82];

        final signatureBytes = hexToBytes(
          '6291d657deec24024827e69c3abe01a3'
          '0ce548a284743a445e3680d7db5ac3ac'
          '18ff9b538d16f290ae67f760984dc659'
          '4a7c15e9716ed28dc027beceea1ec40a',
        );

        final keyPair = KeyPair(
          privateKey: privateKey,
          publicKey: publicKey,
        );

        final signature = Signature(
          signatureBytes,
          publicKey: publicKey,
        );

        test('signSync()', () async {
          final actualSignature = await ed25519.sign(
            message,
            keyPair,
          );
          expect(
            hexFromBytes(actualSignature.bytes),
            hexFromBytes(signature.bytes),
          );
          expect(
            actualSignature.publicKey.bytes,
            keyPair.publicKey.bytes,
          );
        });

        test('signSync(...)', () {
          final actualSignature = ed25519.signSync(
            message,
            keyPair,
          );
          expect(
            hexFromBytes(actualSignature.bytes),
            hexFromBytes(signature.bytes),
          );
          expect(
            actualSignature.publicKey.bytes,
            keyPair.publicKey.bytes,
          );
        });

        test('verify(...)', () async {
          final isOk = await ed25519.verify(
            message,
            signature,
          );
          expect(
            isOk,
            isTrue,
          );
        });

        test('verifySync(...)', () {
          final isOk = ed25519.verifySync(
            message,
            signature,
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
