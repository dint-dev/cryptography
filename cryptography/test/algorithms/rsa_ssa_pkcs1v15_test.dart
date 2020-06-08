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
  group('RsaSsaPkcs1v15:', () {
    final algorithm = RsaPss(sha256);

    test('key pair length is 4096 bits', () async {
      final keyPair = await algorithm.newKeyPair();
      expect(keyPair.publicKey.bytes, hasLength(greaterThan(500)));

      final rsaPrivateKey = keyPair.privateKey as RsaJwkPrivateKey;
      expect(rsaPrivateKey.n, hasLength(4096 ~/ 8));
    });

    test('default exponent is [1,0,1]', () async {
      final keyPair = await algorithm.newKeyPair();
      final rsaPrivateKey = keyPair.privateKey as RsaJwkPrivateKey;
      expect(rsaPrivateKey.e, [1, 0, 1]);
    });

    test('generate key pair, sign, verify (sha256)', () async {
      await _testHashAlgorithm(sha256);
    });

    test('generate key pair, sign, verify (sha384)', () async {
      await _testHashAlgorithm(sha256);
    });

    test('generate key pair, sign, verify (sha512)', () async {
      await _testHashAlgorithm(sha256);
    });
  }, testOn: 'chrome');
}

Future<void> _testHashAlgorithm(HashAlgorithm hashAlgorithm) async {
  final algorithm = RsaPss(hashAlgorithm);

  // Generate key pair
  final keyPair = await algorithm.newKeyPair();
  expect(keyPair, isNotNull);
  keyPair.privateKey.cachedValues.clear();
  keyPair.publicKey.cachedValues.clear();

  final privateKey = keyPair.privateKey as RsaJwkPrivateKey;
  expect(privateKey.n, isNotEmpty);
  expect(privateKey.e, isNotEmpty);
  expect(privateKey.d, isNotEmpty);
  expect(privateKey.p, isNotEmpty);
  expect(privateKey.q, isNotEmpty);
  expect(privateKey.dp, isNotEmpty);
  expect(privateKey.dq, isNotEmpty);
  expect(privateKey.qi, isNotEmpty);

  // Sign
  final signature = await algorithm.sign(
    [1, 2, 3],
    keyPair,
  );
  keyPair.privateKey.cachedValues.clear();
  keyPair.publicKey.cachedValues.clear();

  // Verify the signature
  final isSignatureOk = await algorithm.verify(
    [1, 2, 3],
    signature,
  );
  expect(isSignatureOk, isTrue);

  // Try verify another message with the same signature
  final isWrongSignatureOk = await algorithm.verify(
    [1, 2, 3, 4],
    signature,
  );
  expect(isWrongSignatureOk, isFalse);
}
