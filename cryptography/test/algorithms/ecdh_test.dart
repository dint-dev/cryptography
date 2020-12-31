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

import 'package:cryptography/browser.dart';
import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';

void main() {
  group('Ecdh:', () {
    group('BrowserCryptography:', () {
      setUp(() {
        Cryptography.instance = BrowserCryptography.defaultInstance;
      });
      _main();
    }, testOn: 'chrome');
  });
}

void _main() {
  group('ecdhP256:', () {
    late Ecdh algorithm;
    setUp(() {
      algorithm = Ecdh.p256(length: 32);
    });

    test('generated private key looks normal', () async {
      final keyPair = await algorithm.newKeyPair();
      final keyPairData = await keyPair.extract();
      expect(keyPairData.d, isNotEmpty);
      expect(keyPairData.x, isNotEmpty);
      expect(keyPairData.y, isNotEmpty);
    });

    test('works in browser', () async {
      await _testKeyExchange(algorithm);
    });

    test('generated key pair can be used as ECDSA key pair', () async {
      final keyPair = await algorithm.newKeyPair();

      final message = <int>[1, 2, 3];
      final signatureAlgorithm = Ecdsa.p256(Sha256());
      final signature = await signatureAlgorithm.sign(
        message,
        keyPair: keyPair,
      );
      await signatureAlgorithm.verify(
        message,
        signature: signature,
      );
    });
  });

  group('ecdhP384:', () {
    late Ecdh algorithm;
    setUp(() {
      algorithm = Ecdh.p384(length: 32);
    });

    test('information', () {
      expect(algorithm.keyPairType.ellipticBits, 384);
    });

    test('works in browser', () async {
      await _testKeyExchange(algorithm);
    });
  });

  group('ecdhP521:', () {
    late Ecdh algorithm;
    setUp(() {
      algorithm = Ecdh.p521(length: 32);
    });

    test('information', () {
      expect(algorithm.keyPairType.ellipticBits, 521);
    });

    test('works in browser', () async {
      await _testKeyExchange(algorithm);
    });
  });
}

Future<void> _testKeyExchange(Ecdh algorithm) async {
  // Generate two key pairs
  final keyPair0 = await algorithm.newKeyPair();
  final keyPair1 = await algorithm.newKeyPair();
  final publicKey0 = await keyPair0.extractPublicKey();
  final publicKey1 = await keyPair1.extractPublicKey();

  // Key pairs should be different
  expect(
    keyPair0,
    isNot(keyPair1),
  );
  expect(
    publicKey0,
    isNot(publicKey1),
  );

  // Each generates a shared secret
  final sharedKey0 = await algorithm.sharedSecretKey(
    keyPair: keyPair0,
    remotePublicKey: publicKey1,
  );
  final sharedKey1 = await algorithm.sharedSecretKey(
    keyPair: keyPair1,
    remotePublicKey: publicKey0,
  );

  // The shared secrets are equal
  expect(
    sharedKey0,
    sharedKey1,
    reason: 'Shared keys must be equal',
  );

  {
    final extracted0 = await keyPair0.extract();
    final extracted1 = await keyPair1.extract();
    final newKeyPair0 = EcKeyPairData(
      d: extracted0.d,
      x: extracted0.x,
      y: extracted0.y,
      type: extracted0.type,
    );
    final newKeyPair1 = EcKeyPairData(
      d: extracted1.d,
      x: extracted1.x,
      y: extracted1.y,
      type: extracted1.type,
    );
    final newPublicKey1 = await newKeyPair1.extractPublicKey();
    final newSharedSecretKey = await algorithm.sharedSecretKey(
      keyPair: newKeyPair0,
      remotePublicKey: newPublicKey1,
    );
    expect(
      newSharedSecretKey,
      sharedKey0,
      reason: 'Shared keys must be equal',
    );
  }
}
