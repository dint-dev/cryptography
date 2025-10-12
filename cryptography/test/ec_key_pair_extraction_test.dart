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
import 'package:cryptography_plus/cryptography_plus.dart';
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

    test('information', () {
      expect(algorithm.keyPairType.ellipticBits, 256);
    });

    test('extracting EcKeyPairData', () async {
      final keyPair = await algorithm.newKeyPair();
      final keyPairData = await keyPair.extract();
      expect(keyPairData.type, KeyPairType.p256);
      expect(keyPairData.d, hasLength(32));
      expect(keyPairData.x, hasLength(32));
      expect(keyPairData.y, hasLength(32));
    });

    test('extracting EcPublicKey', () async {
      final keyPair = await algorithm.newKeyPair();
      final publicKey = await keyPair.extractPublicKey();
      expect(publicKey.type, KeyPairType.p256);
      expect(publicKey.x, hasLength(32));
      expect(publicKey.y, hasLength(32));
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

    test('extracting EcKeyPairData', () async {
      final keyPair = await algorithm.newKeyPair();
      final keyPairData = await keyPair.extract();
      expect(keyPairData.type, KeyPairType.p384);
      expect(keyPairData.d, hasLength(48));
      expect(keyPairData.x, hasLength(48));
      expect(keyPairData.y, hasLength(48));
    });

    test('extracting EcPublicKey', () async {
      final keyPair = await algorithm.newKeyPair();
      final publicKey = await keyPair.extractPublicKey();
      expect(publicKey.type, KeyPairType.p384);
      expect(publicKey.x, hasLength(48));
      expect(publicKey.y, hasLength(48));
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

    test('extracting EcKeyPairData', () async {
      final keyPair = await algorithm.newKeyPair();
      final keyPairData = await keyPair.extract();
      expect(keyPairData.type, KeyPairType.p521);
      expect(keyPairData.d, hasLength(66));
      expect(keyPairData.x, hasLength(66));
      expect(keyPairData.y, hasLength(66));
    });

    test('extracting EcPublicKey', () async {
      final keyPair = await algorithm.newKeyPair();
      final publicKey = await keyPair.extractPublicKey();
      expect(publicKey.type, KeyPairType.p521);
      expect(publicKey.x, hasLength(66));
      expect(publicKey.y, hasLength(66));
    });
  });

  group('Ecdsa.p256(Sha256()):', () {
    late Ecdsa algorithm;
    setUp(() {
      algorithm = Ecdsa.p256(Sha256());
    });

    test('information', () {
      expect(algorithm.keyPairType.ellipticBits, 256);
    });

    test('extracting EcKeyPairData', () async {
      final keyPair = await algorithm.newKeyPair();
      final keyPairData = await keyPair.extract();
      expect(keyPairData.type, KeyPairType.p256);
      expect(keyPairData.d, hasLength(32));
      expect(keyPairData.x, hasLength(32));
      expect(keyPairData.y, hasLength(32));
    });

    test('extracting EcPublicKey', () async {
      final keyPair = await algorithm.newKeyPair();
      final publicKey = await keyPair.extractPublicKey();
      expect(publicKey.type, KeyPairType.p256);
      expect(publicKey.x, hasLength(32));
      expect(publicKey.y, hasLength(32));
    });

    test('generated key pair can be used as ECDH key pair', () async {
      final ecdh = Ecdh.p256(length: 32);
      final aliceKeyPair = await algorithm.newKeyPair();
      final bobKeyPair = await algorithm.newKeyPair();
      final bobPublicKey = await bobKeyPair.extractPublicKey();

      await ecdh.sharedSecretKey(
        keyPair: aliceKeyPair,
        remotePublicKey: bobPublicKey,
      );
    });
  });

  group('Ecdsa.p384(Sha384()):', () {
    late Ecdsa algorithm;

    setUp(() {
      algorithm = Ecdsa.p384(Sha384());
    });

    test('information', () {
      expect(algorithm.keyPairType.ellipticBits, 384);
    });

    test('extracting EcKeyPairData', () async {
      final keyPair = await algorithm.newKeyPair();
      final keyPairData = await keyPair.extract();
      expect(keyPairData.type, KeyPairType.p384);
      expect(keyPairData.d, hasLength(48));
      expect(keyPairData.x, hasLength(48));
      expect(keyPairData.y, hasLength(48));
    });

    test('extracting EcPublicKey', () async {
      final keyPair = await algorithm.newKeyPair();
      final publicKey = await keyPair.extractPublicKey();
      expect(publicKey.type, KeyPairType.p384);
      expect(publicKey.x, hasLength(48));
      expect(publicKey.y, hasLength(48));
    });
  });

  group('Ecdsa.p521(Sha512()):', () {
    late Ecdsa algorithm;

    setUp(() {
      algorithm = Ecdsa.p521(Sha512());
    });

    test('information', () {
      expect(algorithm.keyPairType.ellipticBits, 521);
    });

    test('extracting EcKeyPairData', () async {
      final keyPair = await algorithm.newKeyPair();
      final keyPairData = await keyPair.extract();
      expect(keyPairData.type, KeyPairType.p521);
      expect(keyPairData.d, hasLength(66));
      expect(keyPairData.x, hasLength(66));
      expect(keyPairData.y, hasLength(66));
    });

    test('extracting EcPublicKey', () async {
      final keyPair = await algorithm.newKeyPair();
      final publicKey = await keyPair.extractPublicKey();
      expect(publicKey.type, KeyPairType.p521);
      expect(publicKey.x, hasLength(66));
      expect(publicKey.y, hasLength(66));
    });
  });
}
