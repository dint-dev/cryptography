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

import 'dart:typed_data';

import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:cryptography_plus/dart.dart';
import 'package:test/expect.dart';
import 'package:test/scaffolding.dart';

import '../hex.dart';
import '../key_exchange.dart';

void testX25519() {
  testKeyExchangeAlgorithm(
    builder: () {
      return X25519();
    },
    otherTests: () {
      _test();
    },
  );
}

void _test() {
  group(
    'x25519:',
    () {
      test('information', () {
        final algorithm = keyExchangeAlgorithm;
        expect(algorithm.keyPairType, same(KeyPairType.x25519));
        expect(algorithm.keyPairType.name, 'x25519');
        expect(algorithm.keyPairType.publicKeyLength, 32);
      });

      test('1000 random key exchanges', () async {
        final algorithm = X25519();
        for (var i = 0; i < 1000; i++) {
          // Bob and Alice choose a random key pairs
          final aliceKeyPair = await algorithm.newKeyPair();
          final alicePublicKey = await aliceKeyPair.extractPublicKey();

          final bobKeyPair = await algorithm.newKeyPair();
          final bobPublicKey = await bobKeyPair.extractPublicKey();

          // Alice calculates secret
          final aliceShared = await algorithm.sharedSecretKey(
            keyPair: aliceKeyPair,
            remotePublicKey: bobPublicKey,
          );
          final aliceSharedData = await aliceShared.extract();

          // Bob calculates secret
          final bobShared = await algorithm.sharedSecretKey(
            keyPair: bobKeyPair,
            remotePublicKey: alicePublicKey,
          );
          final bobSharedData = await bobShared.extract();

          // The secrets must be the same
          expect(
            hexFromBytes(aliceSharedData.bytes),
            hexFromBytes(bobSharedData.bytes),
          );
        }

        // This takes long time so skip the test in browsers.
      }, testOn: 'vm', timeout: Timeout(const Duration(seconds: 120)));

      test('Test vectors from RFC 7748', () async {
        final algorithm = X25519();

        // The following constants are from RFC 7748:
        // https://tools.ietf.org/html/rfc7748

        final alicePrivateKeyBytes = hexToBytes(
          '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a',
        );

        final alicePublicKeyBytes = hexToBytes(
          '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a',
        );

        final bobPrivateKeyBytes = hexToBytes(
          '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb',
        );

        final bobPublicKeyBytes = hexToBytes(
          'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f',
        );

        final sharedSecretBytes = hexToBytes(
          '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742',
        );

        // Test generating a key pair from seed (for Alice)
        final aliceKeyPair = await algorithm.newKeyPairFromSeed(
          alicePrivateKeyBytes,
        );
        final aliceKeyPairData = await aliceKeyPair.extract();
        expect(aliceKeyPairData.type, KeyPairType.x25519);
        expect(
          aliceKeyPairData.bytes,
          isNot(alicePrivateKeyBytes),
        );
        expect(
          aliceKeyPairData.bytes,
          DartX25519.modifiedPrivateKeyBytes(alicePrivateKeyBytes),
        );
        final alicePublicKey = await aliceKeyPair.extractPublicKey();
        expect(alicePublicKey.type, KeyPairType.x25519);
        expect(
          alicePublicKey.bytes,
          alicePublicKeyBytes,
        );

        // Test generating a key pair from seed (for Bob)
        final bobKeyPair = await algorithm.newKeyPairFromSeed(
          bobPrivateKeyBytes,
        );
        expect(
          await bobKeyPair.extractPrivateKeyBytes(),
          DartX25519.modifiedPrivateKeyBytes(bobPrivateKeyBytes),
        );
        final bobPublicKey = await bobKeyPair.extractPublicKey();
        expect(
          bobPublicKey.bytes,
          bobPublicKeyBytes,
        );

        // Test generating a shared secret (for Alice)
        expect(
          await algorithm
              .sharedSecretKey(
                keyPair: aliceKeyPair,
                remotePublicKey: bobPublicKey,
              )
              .then((value) => value.extractBytes()),
          sharedSecretBytes,
        );

        // Test generating a shared secret (for Bob)
        expect(
          await algorithm
              .sharedSecretKey(
                keyPair: bobKeyPair,
                remotePublicKey: alicePublicKey,
              )
              .then((value) => value.extractBytes()),
          sharedSecretBytes,
        );
      });

      test('public key generation from seed with 10 000 cycles', () async {
        final algorithm = X25519();
        const n = 10000;

        // Initial secret key
        List<int> input = Uint8List(32);
        input[0] = 1;

        // 10 000 times
        for (var i = 0; i < n; i++) {
          // Generate a public key
          final keyPair = await algorithm.newKeyPairFromSeed(
            input,
          );
          final publicKey = await keyPair.extractPublicKey();

          // Use the output as the next input
          input = publicKey.bytes;
        }

        final expected = Uint8List.fromList([
          // Calculated with another implementation.
          138, 8, 200, 47, 95, 126, 210, 241,
          240, 215, 22, 64, 139, 230, 175, 228,
          225, 187, 38, 220, 231, 7, 114, 132,
          215, 244, 136, 80, 47, 52, 92, 15,
        ]);

        expect(input, equals(expected));

        // This takes long time so skip the test in browsers.
      }, testOn: 'vm', timeout: Timeout(const Duration(seconds: 120)));
    },
  );
}
