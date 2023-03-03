// Copyright 2019-2020 Gohilla.
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
import 'package:cryptography/dart.dart';
import 'package:cryptography_flutter/cryptography_flutter.dart';
import 'package:flutter_test/flutter_test.dart';

import '_helpers.dart';

void testKeyExchangeAlgorithms() {
  group('X25519:', () {
    var algorithm = FlutterX25519(BackgroundX25519());
    const dartAlgorithm = DartX25519();
    final defaultAlgorithm = X25519();

    setUp(() {
      algorithm = FlutterX25519(BackgroundX25519());
    });

    const count = 10;

    test(
        '${defaultAlgorithm.runtimeType}.newKeyPair(...): $count times, NOT MUCH SLOWER than the pure Dart implementation',
        () async {
      await expectFasterThanPureDart(
        description: 'When n=$count',
        dart: () => dartAlgorithm.newKeyPair(),
        dartObject: dartAlgorithm,
        benchmarked: () => defaultAlgorithm.newKeyPair(),
        benchmarkedObject: defaultAlgorithm,
        maxRelativeLatency: 4.0,
        n: count,
      );
    });

    test(
        '${defaultAlgorithm.runtimeType}.sharedSecretKey(...): $count times, NOT MUCH SLOWER than the pure Dart implementation',
        () async {
      final keyPair = await defaultAlgorithm.newKeyPair();
      final peerPublicKey =
          await (await defaultAlgorithm.newKeyPair()).extractPublicKey();

      await expectFasterThanPureDart(
        description: 'When n=$count',
        dart: () => dartAlgorithm.sharedSecretKey(
          keyPair: keyPair,
          remotePublicKey: peerPublicKey,
        ),
        dartObject: dartAlgorithm,
        benchmarked: () => defaultAlgorithm.sharedSecretKey(
          keyPair: keyPair,
          remotePublicKey: peerPublicKey,
        ),
        benchmarkedObject: defaultAlgorithm,
        maxRelativeLatency: 4.0,
        n: count,
      );
    });

    test('newKeyPair(...) returns unique, valid keys', () async {
      // Compute key pairs using the platform implementation
      final keyPair0 = (await algorithm.newKeyPair()) as SimpleKeyPairData;
      final keyPair1 = (await algorithm.newKeyPair()) as SimpleKeyPairData;
      expect(keyPair0.bytes, hasLength(32));
      expect(keyPair1.bytes, hasLength(32));
      expect(keyPair0.bytes, isNot(keyPair1.bytes));

      final publicKey0 = await keyPair0.extractPublicKey();
      final publicKey1 = await keyPair1.extractPublicKey();
      expect(publicKey0.bytes, hasLength(32));
      expect(publicKey1.bytes, hasLength(32));
      expect(publicKey0.bytes, isNot(publicKey1.bytes));

      // Validate using the pure Dart implementation
      final secretKey0 = await dartAlgorithm.sharedSecretKey(
        keyPair: keyPair0,
        remotePublicKey: publicKey1,
      );
      final secretKey1 = await dartAlgorithm.sharedSecretKey(
        keyPair: keyPair1,
        remotePublicKey: publicKey0,
      );
      expect(
        secretKey0,
        secretKey1,
        reason: 'Secrets must be equal.',
      );
    });

    test('sharedSecretKey(...): both parties compute the same secret',
        () async {
      // Create key pairs using the pure Dart implementation
      final aliceKeyPair = await dartAlgorithm.newKeyPair();
      final alicePublicKey = await aliceKeyPair.extractPublicKey();
      final bobKeyPair = await dartAlgorithm.newKeyPair();
      final bobPublicKey = await bobKeyPair.extractPublicKey();

      // Compute secret using the platform implementation
      final aliceSecret = await (await algorithm.sharedSecretKey(
        keyPair: aliceKeyPair,
        remotePublicKey: bobPublicKey,
      ))
          .extractBytes();

      final bobSecret = await (await algorithm.sharedSecretKey(
        keyPair: bobKeyPair,
        remotePublicKey: alicePublicKey,
      ))
          .extractBytes();

      expect(aliceSecret, hasLength(32));
      expect(bobSecret, hasLength(32));

      expect(
        aliceSecret,
        bobSecret,
        reason: 'Secrets are different',
      );
    });
  });

  group('Ecdh:', () {
    late Ecdh algorithm;

    setUp(() {
      algorithm = Ecdh.p256(length: 32);
    });

    test('newKeyPair(...) returns unique, valid keys', () async {
      final keyPair0 = await algorithm.newKeyPair() as EcKeyPairData;
      final keyPair1 = await algorithm.newKeyPair() as EcKeyPairData;
      expect(keyPair0, isNot(keyPair1));
    });

    test('sharedSecretKey(...): both parties compute the same secret',
        () async {
      final aliceKeyPair = await algorithm.newKeyPair();
      final alicePublicKey = await aliceKeyPair.extractPublicKey();
      final bobKeyPair = await algorithm.newKeyPair();
      final bobPublicKey = await bobKeyPair.extractPublicKey();

      final aliceSecret = await (await algorithm.sharedSecretKey(
        keyPair: aliceKeyPair,
        remotePublicKey: bobPublicKey,
      ))
          .extractBytes();

      final bobSecret = await (await algorithm.sharedSecretKey(
        keyPair: bobKeyPair,
        remotePublicKey: alicePublicKey,
      ))
          .extractBytes();

      expect(aliceSecret, hasLength(32));
      expect(bobSecret, hasLength(32));

      expect(
        aliceSecret,
        bobSecret,
        reason: 'Secrets are different',
      );
    });
  }, skip: '!chrome');
}
