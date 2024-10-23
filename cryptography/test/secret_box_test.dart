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

import 'dart:typed_data';

import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:test/test.dart';

void main() {
  group('SecretBox:', () {
    test('"==" / hashCode', () {
      final value = SecretBox(
        [1],
        nonce: [2],
        mac: Mac([3]),
      );
      final clone = SecretBox(
        [1],
        nonce: [2],
        mac: Mac([3]),
      );
      final other0 = SecretBox(
        [9999],
        nonce: [2],
        mac: Mac([3]),
      );
      final other1 = SecretBox(
        [1],
        nonce: [9999],
        mac: Mac([3]),
      );
      final other2 = SecretBox(
        [1],
        nonce: [2],
        mac: Mac([9999]),
      );

      expect(value, clone);
      expect(value, isNot(other0));
      expect(value, isNot(other1));
      expect(value, isNot(other2));

      expect(value.hashCode, clone.hashCode);
      expect(value.hashCode, isNot(other0.hashCode));
      expect(value.hashCode, isNot(other1.hashCode));
      expect(value.hashCode, isNot(other2.hashCode));
    });

    test('toString() shows only `nonce` and `mac`', () {
      final secretBox = SecretBox(
        Uint8List(100),
        nonce: [1, 2],
        mac: const Mac([3, 4]),
      );
      expect(
        secretBox.toString(),
        'SecretBox(\n'
        '  [~~100 bytes~~],\n'
        '  nonce: [1,2],\n'
        '  mac: Mac([3,4]),\n'
        ')',
      );
    });

    // checkMac() is tested in other tests too, but some redundancy is good.
    test('checkMac()', () async {
      final algorithm = Chacha20(macAlgorithm: Poly1305());
      final clearText = [1, 2, 3];
      final secretKey = await algorithm.newSecretKey();
      final secretBox = await algorithm.encrypt(
        clearText,
        secretKey: secretKey,
      );
      final invalidSecretBox = SecretBox(
        secretBox.cipherText,
        nonce: secretBox.nonce,
        mac: Mac(secretBox.mac.bytes.map((e) => 0xFF ^ e).toList()),
      );

      // Checking valid secret box does not throw
      await secretBox.checkMac(
        macAlgorithm: algorithm.macAlgorithm,
        secretKey: secretKey,
        aad: [],
      );

      // Checking invalid secret box will throw
      try {
        await invalidSecretBox.checkMac(
          macAlgorithm: algorithm.macAlgorithm,
          secretKey: secretKey,
          aad: [],
        );
        fail('Should have thrown.');
      } on SecretBoxAuthenticationError {
        // OK.
      }
    });

    test('fromConcatenation([1,2,3], nonceLength: 0, macLength: 0)', () {
      final secretBox = SecretBox.fromConcatenation(
        [1, 2, 3],
        nonceLength: 0,
        macLength: 0,
      );
      expect(secretBox.nonce, []);
      expect(secretBox.cipherText, [1, 2, 3]);
      expect(secretBox.mac, Mac([]));
    });

    test('fromConcatenation([1,2,3,4,5], nonceLength: 2, macLength: 0)', () {
      final secretBox = SecretBox.fromConcatenation(
        [1, 2, 3, 4, 5],
        nonceLength: 2,
        macLength: 0,
      );
      expect(secretBox.nonce, [1, 2]);
      expect(secretBox.cipherText, [3, 4, 5]);
      expect(secretBox.mac, Mac([]));
    });

    test('fromConcatenation([1,2,3,4,5], nonceLength: 0, macLength: 3)', () {
      final secretBox = SecretBox.fromConcatenation(
        [1, 2, 3, 4, 5],
        nonceLength: 0,
        macLength: 3,
      );
      expect(secretBox.nonce, []);
      expect(secretBox.cipherText, [1, 2]);
      expect(secretBox.mac, Mac([3, 4, 5]));
    });

    test('fromConcatenation([1,2,3,4,5,6], nonceLength: 2, macLength: 3)', () {
      final secretBox = SecretBox.fromConcatenation(
        [1, 2, 3, 4, 5, 6],
        nonceLength: 2,
        macLength: 3,
      );
      expect(secretBox.nonce, [1, 2]);
      expect(secretBox.cipherText, [3]);
      expect(secretBox.mac, Mac([4, 5, 6]));
    });

    test('concatenation(nonce: false, mac: false)', () {
      final secretBox = SecretBox(
        [3, 4],
        nonce: [1, 2],
        mac: Mac([5, 6]),
      );
      expect(secretBox.concatenation(nonce: false, mac: false), [3, 4]);
    });

    test('concatenation(nonce: false, mac: true)', () {
      final secretBox = SecretBox(
        [3, 4],
        nonce: [1, 2],
        mac: Mac([5, 6]),
      );
      expect(secretBox.concatenation(nonce: false, mac: true), [3, 4, 5, 6]);
    });

    test('concatenation(nonce: true, mac: false)', () {
      final secretBox = SecretBox(
        [3, 4],
        nonce: [1, 2],
        mac: Mac([5, 6]),
      );
      expect(secretBox.concatenation(nonce: true, mac: false), [1, 2, 3, 4]);
    });

    test('concatenation(nonce: true, mac: true)', () {
      final secretBox = SecretBox(
        [3, 4],
        nonce: [1, 2],
        mac: Mac([5, 6]),
      );
      expect(secretBox.concatenation(), [1, 2, 3, 4, 5, 6]);
    });
  });
}
