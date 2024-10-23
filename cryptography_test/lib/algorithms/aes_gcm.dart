// Copyright 2023 Gohilla.
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

import 'dart:typed_data';

import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:test/expect.dart';
import 'package:test/scaffolding.dart';

import '../cipher.dart';
import '../hex.dart';

void testAesGcm() {
  testCipher(
    builder: () => AesGcm.with128bits(),
  );
  testCipher(
    builder: () => AesGcm.with192bits(),
  );
  testCipher(
    builder: () => AesGcm.with256bits(),
    otherTests: (cipher) {
      //
      // The following test vectors were calculated with Web Cryptography API.
      //

      test('AesGcm.with128bits(): 1 000 cycles', () async {
        await _testAesGcmExample(
          algorithm: AesGcm.with128bits(),
          expectedHex: ''
              'f3 52 fb 3f a0 3d 70 25 f3 0f 48 01 eb 3a d2 85\n'
              '89 53 06 4d 8c 53 25 38 96 ca 71 c2 90 f0 3b 06',
        );
      });

      test('AesGcm.with128bits(): 1 000 cycles, AAD', () async {
        await _testAesGcmExample(
          algorithm: AesGcm.with128bits(),
          aad: [1, 2, 3],
          expectedHex: ''
              'e5 a3 57 59 6c 11 c0 ab 18 e6 b3 f5 71 6a f9 46\n'
              '25 ce 95 7d eb 29 c4 bf 24 80 6d 33 e2 f5 1f 2b',
        );
      });

      test('AesGcm.with192bits(): 1 000 cycles, AAD', () async {
        await _testAesGcmExample(
          algorithm: AesGcm.with192bits(),
          aad: [1, 2, 3],
          expectedHex: ''
              '76 5d 6c 02 16 56 a0 ef 22 e1 97 5c 4b 81 fc 36\n'
              '2b 9c 5a da d9 2d 6c d5 c9 94 c7 a2 c8 73 e7 ab',
        );
      });

      test('AesGcm.with256bits(): 1 000 cycles', () async {
        await _testAesGcmExample(
          algorithm: AesGcm.with256bits(),
          expectedHex: ''
              '2e f9 45 f9 4b 94 43 d9 1a 43 3d c2 e4 40 c0 0f\n'
              '20 27 0d 93 3d 47 ae 44 41 29 6e 3c 32 27 97 ef',
        );
      });

      test('AesGcm.with256bits(): 1 000 cycles, AAD', () async {
        await _testAesGcmExample(
          algorithm: AesGcm.with256bits(),
          aad: [1, 2, 3],
          expectedHex: ''
              '52 dd c6 e5 07 65 f1 46 7e 1c 5a f5 9f cb 0c 69\n'
              '84 11 c1 52 83 08 b5 3b 19 28 d5 79 bd 2f aa c7',
        );
      });
    },
  );
}

Future<void> _testAesGcmExample({
  required AesGcm algorithm,
  List<int> aad = const [],
  int rounds = 1000,
  required String expectedHex,
}) async {
  var secretKeyBytes = hexToBytes(
    '02020202020202020202020202020202'
    '02020202020202020202020202020202',
  ).sublist(0, algorithm.secretKeyLength);
  var nonce = hexToBytes(
    '03030303030303030303030303030303',
  );
  final hashAlgorithm = Sha256();

  var data = List<int>.filled(rounds + 1000, 1);
  late Mac mac;
  for (var i = 0; i < rounds; i++) {
    // Encrypt
    final secretBox = await algorithm.encrypt(
      data,
      secretKey: SecretKey(secretKeyBytes),
      nonce: nonce,
      aad: aad,
    );
    expect(secretBox.nonce, nonce);
    mac = secretBox.mac;
    expect(mac.bytes, hasLength(16));

    // Test that decryption works
    final decryptedSecretBox = await algorithm.decrypt(
      secretBox,
      secretKey: SecretKey(secretKeyBytes),
      aad: aad,
    );
    expect(decryptedSecretBox, data);

    // Change data.
    // Put MAC somewhere in the data.
    data = Uint8List.fromList(secretBox.cipherText);
    data.setRange(100, 100 + 16, secretBox.mac.bytes);

    // Change size for the next round
    data = data.sublist(1);

    // Change  secret key
    secretKeyBytes = (await hashAlgorithm.hash(data))
        .bytes
        .sublist(0, algorithm.secretKeyLength);

    // Change nonce
    nonce = (await hashAlgorithm.hash(secretKeyBytes)).bytes.sublist(0, 12);
  }

  expect(data, hasLength(1000));
  final hash = await hashAlgorithm.hash(data);
  expect(
    hexFromBytes(hash.bytes),
    expectedHex,
  );

  // We don't need to test MAC because its part of the clearText at each round
  // after the first one.
}
