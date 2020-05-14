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

    test('works in browser', () async {
      await _testKeyExchange(algorithm);
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
}
