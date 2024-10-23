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
  group('RsaPss:', () {
    late RsaPss algorithm;
    setUp(() {
      algorithm = RsaPss(Sha256());
    });

    test('equality / hashCode', () async {
      final clone = RsaPss(Sha256());
      final other = RsaPss(Sha1());
      expect(algorithm, clone);
      expect(algorithm, isNot(other));
      expect(algorithm.hashCode, clone.hashCode);
      expect(algorithm.hashCode, isNot(other.hashCode));
    });

    test('"n" is 4096 bits', () async {
      final secretKey = await algorithm.newKeyPair();
      final rsaKeyPair = await secretKey.extract();
      final publicKey = await secretKey.extractPublicKey();
      expect(rsaKeyPair.n, hasLength(4096 ~/ 8));
      expect(publicKey.n, rsaKeyPair.n);
    });

    test('"n" is a random 4096 bit number', () async {
      final secretKey0 = await algorithm.newKeyPair();
      final secretKey1 = await algorithm.newKeyPair();
      final rsaSecretKey0 = await secretKey0.extract();
      final rsaSecretKey1 = await secretKey1.extract();
      expect(rsaSecretKey0.n, hasLength(4096 / 8));
      expect(rsaSecretKey0.n, isNot(rsaSecretKey1.n));
      expect(rsaSecretKey0, isNot(rsaSecretKey1));
      expect(secretKey0, isNot(secretKey1));
    });

    test('default exponent is [1,0,1]', () async {
      final secretKey = await algorithm.newKeyPair();
      final rsaSecretKey = await secretKey.extract();
      final publicKey = await secretKey.extractPublicKey();
      expect(rsaSecretKey.e, [1, 0, 1]);
      expect(publicKey.e, [1, 0, 1]);
    });

    test('generate key pair, sign, verify (sha1)', () async {
      await _testHashAlgorithm(Sha1());
    });

    test('generate key pair, sign, verify (sha256)', () async {
      await _testHashAlgorithm(Sha256());
    });

    test('generate key pair, sign, verify (sha384)', () async {
      await _testHashAlgorithm(Sha384());
    });

    test('generate key pair, sign, verify (sha512)', () async {
      await _testHashAlgorithm(Sha512());
    });
  }, testOn: 'chrome');
}

Future<void> _testHashAlgorithm(HashAlgorithm hashAlgorithm) async {
  final algorithm = RsaPss(hashAlgorithm);

  // Generate key pair
  final opaqueSecretKey = await algorithm.newKeyPair();
  final secretKey = await opaqueSecretKey.extract();
  expect(secretKey.n, isNotEmpty);
  expect(secretKey.e, isNotEmpty);
  expect(secretKey.d, isNotEmpty);
  expect(secretKey.p, isNotEmpty);
  expect(secretKey.q, isNotEmpty);
  expect(secretKey.dp, isNotEmpty);
  expect(secretKey.dq, isNotEmpty);
  expect(secretKey.qi, isNotEmpty);

  // Sign
  const message = <int>[1, 2, 3];
  final signature = await algorithm.sign(
    message,
    keyPair: secretKey,
  );
  expect(signature.bytes, isNotEmpty);
  expect(signature.publicKey, isA<RsaPublicKey>());

  // Verify the signature
  {
    final isSignatureOk = await algorithm.verify(
      message,
      signature: signature,
    );
    expect(isSignatureOk, isTrue);
  }

  // Verify the signature
  {
    final isSignatureOk = await algorithm.verify(
      message,
      signature: signature,
    );
    expect(isSignatureOk, isTrue);
  }

  // Try verify another message with the same signature
  final isWrongSignatureOk = await algorithm.verify(
    [...message, 4],
    signature: signature,
  );
  expect(isWrongSignatureOk, isFalse);
}
