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
import 'package:test/test.dart';

void main() {
  group('Ecdsa:', () {
    group('BrowserCryptography:', () {
      setUp(() {
        Cryptography.instance = BrowserCryptography.defaultInstance;
      });
      _main();
    }, testOn: 'chrome');
  });
}

void _main() {
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

    test('works in browser', () async {
      await _testSignature(algorithm);
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

    test('works in browser', () async {
      await _testSignature(algorithm);
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

    test('works in browser', () async {
      await _testSignature(algorithm);
    });
  });
}

Future<void> _testSignature(Ecdsa algorithm) async {
  // Generate two key pairs
  final keyPair = await algorithm.newKeyPair();
  final otherKeyPair = await algorithm.newKeyPair();
  final otherPublicKey = await otherKeyPair.extractPublicKey();

  // Key pairs should be different
  expect(
    keyPair,
    isNot(otherKeyPair),
    reason: 'Two random key pairs must be non-equal',
  );

  // OK: Sign
  final message = const <int>[1, 2, 3];
  final signature = await algorithm.sign(
    message,
    keyPair: keyPair,
  );
  final signatureAgain = await algorithm.sign(
    message,
    keyPair: keyPair,
  );
  expect(
    signatureAgain,
    isNot(signature),
    reason: 'Two signatures with the same arguments must be non-equal',
  );

  // OK: Verify
  expect(
    await algorithm.verify(
      message,
      signature: signature,
    ),
    isTrue,
    reason: 'Signature verification must succeed',
  );

  expect(
    await algorithm.verify(
      const [],
      signature: signature,
    ),
    isFalse,
    reason: 'Signature verification must fail when the message is different',
  );

  expect(
    await algorithm.verify(
      message,
      signature: Signature(
        signature.bytes,
        publicKey: otherPublicKey,
      ),
    ),
    isFalse,
    reason: 'Signature verification must fail when the public key is different',
  );

  // Reconstruct the key pair and sign again
  final extracted = await keyPair.extract();
  final keyPairClone = EcKeyPairData(
    d: extracted.d,
    x: extracted.x,
    y: extracted.y,
    type: extracted.type,
  );
  expect(
    keyPairClone,
    extracted,
    reason: 'Cloned key pair must be equal',
  );
  final signatureClone = await algorithm.sign(
    message,
    keyPair: keyPairClone,
  );
  final isOk = await algorithm.verify(
    message,
    signature: signatureClone,
  );
  expect(isOk, isTrue);
}
