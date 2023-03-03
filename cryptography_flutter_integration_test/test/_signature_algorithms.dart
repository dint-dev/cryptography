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
import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';

import '_helpers.dart';

void testSignatureAlgorithms() {
  group('Ed25519:', () {
    var algorithm = FlutterEd25519(BackgroundEd25519());
    final dartAlgorithm = DartEd25519();
    var defaultAlgorithm = Ed25519();

    setUp(() {
      algorithm = FlutterEd25519(BackgroundEd25519());
    });

    test(
        '${defaultAlgorithm.runtimeType}: newKeyPair(...): NOT MUCH SLOWER than the pure Dart implementation',
        () async {
      const n = 10;
      await expectFasterThanPureDart(
        description: 'When n=$n',
        dart: () => dartAlgorithm.newKeyPair(),
        dartObject: dartAlgorithm,
        benchmarked: () => defaultAlgorithm.newKeyPair(),
        benchmarkedObject: defaultAlgorithm,
        maxRelativeLatency: 3.0,
        n: n,
      );
    });

    test(
        '${defaultAlgorithm.runtimeType}: sign(...): NOT MUCH SLOWER than the pure Dart implementation, 100 bytes',
        () async {
      final data = Uint8List(100);
      final dartKeyPair = await dartAlgorithm.newKeyPair();
      final flutterKeyPair = await defaultAlgorithm.newKeyPair();

      const n = 10;
      await expectFasterThanPureDart(
        description: 'When data is 100 bytes, n=$n',
        dart: () => dartAlgorithm.sign(data, keyPair: dartKeyPair),
        dartObject: dartAlgorithm,
        benchmarked: () => defaultAlgorithm.sign(data, keyPair: flutterKeyPair),
        benchmarkedObject: defaultAlgorithm,
        maxRelativeLatency: 4.0,
        n: n,
      );
    });

    test(
        '${defaultAlgorithm.runtimeType}: sign(...): NOT MUCH SLOWER than the pure Dart implementation, 1 megabyte',
        () async {
      final data = Uint8List(1000 * 1000);
      final dartKeyPair = await dartAlgorithm.newKeyPair();
      final flutterKeyPair = await defaultAlgorithm.newKeyPair();

      const n = 10;
      await expectFasterThanPureDart(
        description: 'When data is 1 MB, n=$n',
        dart: () => dartAlgorithm.sign(data, keyPair: dartKeyPair),
        dartObject: dartAlgorithm,
        benchmarked: () => defaultAlgorithm.sign(data, keyPair: flutterKeyPair),
        benchmarkedObject: defaultAlgorithm,
        maxRelativeLatency: 4.0,
        n: n,
      );
    });

    test('newKeyPair(...) returns unique, valid key pairs', () async {
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

      final signature0 = await dartAlgorithm.sign(
        [1, 2, 3],
        keyPair: keyPair0,
      );
      expect(
        await dartAlgorithm.verify(
          [1, 2, 3],
          signature: signature0,
        ),
        isTrue,
      );
      expect(
        await dartAlgorithm.verify(
          [0, 0, 0],
          signature: signature0,
        ),
        isFalse,
      );
    });

    test('sign(...)', () async {
      final keyPair = await dartAlgorithm.newKeyPair();
      final expectedPublicKey = await keyPair.extractPublicKey();
      final data = Uint8List.fromList('Hello, world!'.codeUnits);

      final signature = await algorithm.sign(data, keyPair: keyPair);
      expect(
        signature.bytes,
        hasLength(64),
        reason: 'Signature should have the correct length.',
      );
      expect(
        signature.publicKey,
        expectedPublicKey,
        reason: 'Signature should have the same public key.',
      );

      // Test using the pure Dart implementation.
      expect(
        await dartAlgorithm.verify(
          data,
          signature: signature,
        ),
        isTrue,
      );
      expect(
        await dartAlgorithm.verify(
          List<int>.filled(data.length, 0),
          signature: signature,
        ),
        isFalse,
      );
    });

    test('verify(...) when signature is valid', () async {
      final keyPair = await dartAlgorithm.newKeyPair();
      final data = Uint8List.fromList('Hello, world!'.codeUnits);
      final signature = await dartAlgorithm.sign(data, keyPair: keyPair);

      final isOk = await algorithm.verify(
        data,
        signature: signature,
      );
      expect(isOk, isTrue);
    });

    test('verify(...) when signature is invalid', () async {
      final keyPair = await dartAlgorithm.newKeyPair();
      final data = Uint8List.fromList('Hello, world!'.codeUnits);
      final signature = await dartAlgorithm.sign(data, keyPair: keyPair);

      final otherData = Uint8List.fromList('HELLO, WORLD!'.codeUnits);
      final isOk = await algorithm.verify(
        otherData,
        signature: signature,
      );
      expect(isOk, isFalse);
    });
  });

  group('Ecdsa:', () {
    final algorithm = FlutterEcdsa.p384(Sha256());

    test('newKeyPair(...) returns unique, valid keys', () async {
      final keyPair0 = await algorithm.newKeyPair() as EcKeyPairData;
      final keyPair1 = await algorithm.newKeyPair() as EcKeyPairData;
      expect(keyPair0, isNot(keyPair1));
    });

    test('sign(...)', () async {
      final keyPair = await algorithm.newKeyPair();
      final data = [1, 2, 3];

      final signature = await algorithm.sign(data, keyPair: keyPair);
      expect(
        signature.bytes,
        hasLength(64),
        reason: 'Signature should have the correct length.',
      );
      expect(
        signature.publicKey,
        await keyPair.extractPublicKey(),
        reason: 'Signature should have the same public key.',
      );

      expect(
        await algorithm.verify(
          data,
          signature: signature,
        ),
        isTrue,
        reason: 'verify() should return true',
      );
      expect(
        await algorithm.verify(
          List<int>.filled(data.length, 0),
          signature: signature,
        ),
        isFalse,
        reason: 'verify() should return false',
      );
    });
  }, skip: '!chrome');

  group('RsaPss:', () {
    var algorithm = FlutterRsaPss(DartRsaPss(Sha256()));

    test('newKeyPair(...) returns unique, valid keys', () async {
      final keyPair0 = await algorithm.newKeyPair() as RsaKeyPairData;
      final keyPair1 = await algorithm.newKeyPair() as RsaKeyPairData;
      expect(keyPair0, isNot(keyPair1));
    });
    test('sign(...)', () async {
      final keyPair = await algorithm.newKeyPair();
      final data = [1, 2, 3];

      final signature = await algorithm.sign(data, keyPair: keyPair);
      expect(
        signature.bytes,
        hasLength(64),
        reason: 'Signature should have the correct length.',
      );
      expect(
        signature.publicKey,
        await keyPair.extractPublicKey(),
        reason: 'Signature should have the same public key.',
      );

      expect(
        await algorithm.verify(
          data,
          signature: signature,
        ),
        isTrue,
        reason: 'verify() should return true',
      );
      expect(
        await algorithm.verify(
          List<int>.filled(data.length, 0),
          signature: signature,
        ),
        isFalse,
        reason: 'verify() should return false',
      );
    });
  }, skip: '!chrome');

  group('RsaSsaPkcs1v15:', () {
    var algorithm = FlutterRsaSsaPkcs1v15(DartRsaSsaPkcs1v15(Sha256()));

    test('FlutterCryptography factory method', () {
      expect(algorithm, isA<FlutterRsaSsaPkcs1v15>());
    });

    test('newKeyPair(...) returns unique, valid keys', () async {
      final keyPair0 = await algorithm.newKeyPair() as RsaKeyPairData;
      final keyPair1 = await algorithm.newKeyPair() as RsaKeyPairData;
      expect(keyPair0, isNot(keyPair1));
    });

    test('sign(...)', () async {
      final keyPair = await algorithm.newKeyPair();
      final data = [1, 2, 3];

      final signature = await algorithm.sign(data, keyPair: keyPair);
      expect(
        signature.bytes,
        hasLength(64),
        reason: 'Signature should have the correct length.',
      );
      expect(
        signature.publicKey,
        await keyPair.extractPublicKey(),
        reason: 'Signature should have the same public key.',
      );

      expect(
        await algorithm.verify(
          data,
          signature: signature,
        ),
        isTrue,
        reason: 'verify() should return true',
      );
      expect(
        await algorithm.verify(
          List<int>.filled(data.length, 0),
          signature: signature,
        ),
        isFalse,
        reason: 'verify() should return false',
      );
    });
  }, skip: '!chrome');
}
