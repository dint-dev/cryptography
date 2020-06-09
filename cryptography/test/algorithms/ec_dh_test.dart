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
  group('ecdhP256:', () {
    const algorithm = ecdhP256;

    test('information', () {
      expect(algorithm.name, 'ecdhP256');
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
      await _testKeyExchange(algorithm);
    }, testOn: 'chrome');

    test('generated key pair can be used as ECDSA key pair', () async {
      final keyPair = await algorithm.newKeyPair();

      final message = <int>[1, 2, 3];
      final signature = await ecdsaP256Sha256.sign(message, keyPair);
      await ecdsaP256Sha256.verify(message, signature);
    }, testOn: 'chrome');
  });

  group('ecdhP384:', () {
    const algorithm = ecdhP384;

    test('information', () {
      expect(algorithm.name, 'ecdhP384');
      expect(algorithm.publicKeyLength, 48);
    });

    test('works in browser', () async {
      await _testKeyExchange(algorithm);
    }, testOn: 'chrome');
  });

  group('ecdhP521:', () {
    const algorithm = ecdhP521;

    test('information', () {
      expect(algorithm.name, 'ecdhP521');
      expect(algorithm.publicKeyLength, 66);
    });

    test('works in browser', () async {
      await _testKeyExchange(algorithm);
    }, testOn: 'chrome');
  });
}

Future<void> _testKeyExchange(KeyExchangeAlgorithm algorithm) async {
  // Generate two key pairs
  final keypair0 = await algorithm.newKeyPair();
  final keypair1 = await algorithm.newKeyPair();

  // Key pairs should be different
  expect(
    keypair0.privateKey,
    isNot(keypair1.privateKey),
  );
  expect(
    keypair0.publicKey,
    isNot(keypair1.publicKey),
  );

  expect(keypair0.privateKey, isA<EcJwkPrivateKey>());

  // Each generates a shared secret
  final sharedKey0 = await algorithm.sharedSecret(
    localPrivateKey: keypair0.privateKey,
    remotePublicKey: keypair1.publicKey,
  );
  final sharedKey1 = await algorithm.sharedSecret(
    localPrivateKey: keypair1.privateKey,
    remotePublicKey: keypair0.publicKey,
  );

  // The shared secrets are equal
  expect(
    sharedKey0,
    sharedKey1,
  );

  {
    // Reconstruct the key pair
    final newKeyPair0 = KeyPair(
      privateKey: PrivateKey(keypair0.privateKey.extractSync()),
      publicKey: PublicKey(keypair0.publicKey.bytes),
    );

    final newSharedKey0 = await algorithm.sharedSecret(
      localPrivateKey: newKeyPair0.privateKey,
      remotePublicKey: keypair1.publicKey,
    );

    final newSharedKey1 = await algorithm.sharedSecret(
      localPrivateKey: keypair1.privateKey,
      remotePublicKey: newKeyPair0.publicKey,
    );

    expect(
      sharedKey0,
      newSharedKey0,
    );

    expect(
      sharedKey0,
      newSharedKey1,
    );
  }
}
