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
  group('RsaSsaPkcs1v15:', () {
    _main();
  }, testOn: 'chrome');
}

void _main() {
  late RsaSsaPkcs1v15 algorithm;
  setUp(() {
    algorithm = RsaSsaPkcs1v15(Sha256());
  });

  test('equality / hashCode', () async {
    final clone = RsaSsaPkcs1v15(Sha256());
    final other = RsaSsaPkcs1v15(Sha1());
    expect(algorithm, clone);
    expect(algorithm, isNot(other));
    expect(algorithm.hashCode, clone.hashCode);
    expect(algorithm.hashCode, isNot(other.hashCode));
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
}

Future<void> _testHashAlgorithm(HashAlgorithm hashAlgorithm) async {
  final algorithm = RsaSsaPkcs1v15(hashAlgorithm);

  // Generate key pair
  final keyPair = await algorithm.newKeyPair();
  final extractedKeyPair = await keyPair.extract();
  expect(extractedKeyPair.n, isNotEmpty);
  expect(extractedKeyPair.e, isNotEmpty);
  expect(extractedKeyPair.d, isNotEmpty);
  expect(extractedKeyPair.p, isNotEmpty);
  expect(extractedKeyPair.q, isNotEmpty);
  expect(extractedKeyPair.dp, isNotEmpty);
  expect(extractedKeyPair.dq, isNotEmpty);
  expect(extractedKeyPair.qi, isNotEmpty);

  // Sign
  const message = <int>[1, 2, 3];
  final signature = await algorithm.sign(
    message,
    keyPair: extractedKeyPair,
  );

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
