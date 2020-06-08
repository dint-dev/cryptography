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
import 'package:test/test.dart';

void main() {
  group('ecdsaP256Sha256:', () {
    const algorithm = ecdsaP256Sha256;

    test('information', () {
      expect(algorithm.name, 'ecdsaP256Sha256');
      expect(algorithm.publicKeyLength, 32);
    });

    test('generated private key looks normal', () async {
      final keyPair = await algorithm.newKeyPair();
      expect(keyPair.privateKey, isA<EcJwkPrivateKey>());

      final privateKey = keyPair.privateKey as EcJwkPrivateKey;
      expect(privateKey.d, isNotEmpty);
      expect(privateKey.x, isNotEmpty);
      expect(privateKey.y, isNotEmpty);
    }, testOn: 'chrome');

    test('works in browser', () async {
      await _testSignature(algorithm);
    }, testOn: 'chrome');
  });

  group('ecdsaP384Sha256:', () {
    const algorithm = ecdsaP384Sha256;

    test('information', () {
      expect(algorithm.name, 'ecdsaP384Sha256');
      expect(algorithm.publicKeyLength, 48);
    });

    test('generated private key looks normal', () async {
      final keyPair = await algorithm.newKeyPair();
      expect(keyPair.privateKey, isA<EcJwkPrivateKey>());

      final privateKey = keyPair.privateKey as EcJwkPrivateKey;
      expect(privateKey.d, isNotEmpty);
      expect(privateKey.x, isNotEmpty);
      expect(privateKey.y, isNotEmpty);
    }, testOn: 'chrome');

    test('works in browser', () async {
      await _testSignature(algorithm);
    }, testOn: 'chrome');
  });

  group('ecdsaP384Sha384:', () {
    const algorithm = ecdsaP384Sha384;

    test('information', () {
      expect(algorithm.name, 'ecdsaP384Sha384');
      expect(algorithm.publicKeyLength, 48);
    });

    test('works in browser', () async {
      await _testSignature(algorithm);
    }, testOn: 'chrome');
  });

  group('ecdsaP521Sha256:', () {
    const algorithm = ecdsaP521Sha256;

    test('information', () {
      expect(algorithm.name, 'ecdsaP521Sha256');
      expect(algorithm.publicKeyLength, 66);
    });

    test('generated private key looks normal', () async {
      final keyPair = await algorithm.newKeyPair();
      expect(keyPair.privateKey, isA<EcJwkPrivateKey>());

      final privateKey = keyPair.privateKey as EcJwkPrivateKey;
      expect(privateKey.d, isNotEmpty);
      expect(privateKey.x, isNotEmpty);
      expect(privateKey.y, isNotEmpty);
    }, testOn: 'chrome');

    test('works in browser', () async {
      await _testSignature(algorithm);
    }, testOn: 'chrome');
  });

  group('ecdsaP521Sha512:', () {
    const algorithm = ecdsaP521Sha512;

    test('information', () {
      expect(algorithm.name, 'ecdsaP521Sha512');
      expect(algorithm.publicKeyLength, 66);
    });

    test('works in browser', () async {
      await _testSignature(algorithm);
    }, testOn: 'chrome');
  });
}

Future<void> _testSignature(SignatureAlgorithm algorithm) async {
  // Generate two key pairs
  final keypair = await algorithm.newKeyPair();
  final otherKeyPair = await algorithm.newKeyPair();

  // Key pairs should be different
  expect(
    keypair.privateKey,
    isNot(otherKeyPair.privateKey),
  );
  expect(
    keypair.publicKey,
    isNot(otherKeyPair.publicKey),
  );

  // OK: Sign
  final message = const <int>[1, 2, 3];
  final signature = await algorithm.sign(
    message,
    keypair,
  );

  // OK: Verify
  expect(
    await algorithm.verify(message, signature),
    isTrue,
  );

  // Should fail: Verify some other message using the same signature.
  expect(
    await algorithm.verify(const [], signature),
    isFalse,
  );

  // Should fail: Verify the same message with a different public key.
  expect(
    await algorithm.verify(
      message,
      Signature(signature.bytes, publicKey: otherKeyPair.publicKey),
    ),
    isFalse,
  );
}
