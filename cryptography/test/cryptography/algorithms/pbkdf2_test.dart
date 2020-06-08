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
import 'package:cryptography/src/utils.dart';
import 'package:test/test.dart';

void main() {
  group('Pbkdf2:', () {
    test('deriveBits(...): Hmac(sha256), 1 iteration', () async {
      final macAlgorithm = Hmac(sha256);
      final input = <int>[1, 2, 3];
      final nonce = Nonce([4, 5, 6]);
      final bits = 128;
      final iterations = 1;
      final expected = hexToBytes(
        '3f 22 41 8b c0 47 83 9f b5 54 b5 c6 16 ef 35 55',
      );

      final pbkdf2 = Pbkdf2(
        macAlgorithm: macAlgorithm,
        bits: bits,
        iterations: iterations,
      );
      final actual = await pbkdf2.deriveBits(
        input,
        nonce: nonce,
      );
      expect(
        hexFromBytes(actual),
        hexFromBytes(expected),
      );
    });

    test('deriveBits(...): Hmac(sha256), 2 iterations', () async {
      final macAlgorithm = Hmac(sha256);
      final input = <int>[1, 2, 3];
      final nonce = Nonce([4, 5, 6]);
      final bits = 128;
      final iterations = 2;
      final expected = hexToBytes(
        '43 bb 42 58 d4 54 0e d2 45 c3 87 78 8b 60 5d 95',
      );

      final pbkdf2 = Pbkdf2(
        macAlgorithm: macAlgorithm,
        bits: bits,
        iterations: iterations,
      );
      final actual = await pbkdf2.deriveBits(
        input,
        nonce: nonce,
      );
      expect(
        hexFromBytes(actual),
        hexFromBytes(expected),
      );
    });

    test('deriveBits(...): Hmac(sha256), 3 iterations', () async {
      final macAlgorithm = Hmac(sha256);
      final input = <int>[1, 2, 3];
      final nonce = Nonce([4, 5, 6]);
      final bits = 128;
      final iterations = 3;
      final expected = hexToBytes(
        '00 4b 50 3c 32 a1 b7 44 ca 98 a9 ce 2e 17 23 18',
      );

      final pbkdf2 = Pbkdf2(
        macAlgorithm: macAlgorithm,
        bits: bits,
        iterations: iterations,
      );
      final actual = await pbkdf2.deriveBits(
        input,
        nonce: nonce,
      );
      expect(
        hexFromBytes(actual),
        hexFromBytes(expected),
      );
    });

    test('deriveBitsSync(...): Hmac(sha256)', () async {
      final macAlgorithm = Hmac(sha256);
      final input = <int>[1, 2];
      final nonce = Nonce([3, 4]);
      final bits = 128;
      final iterations = 3;
      final expected = hexToBytes(
        '4b 15 52 46 08 c4 32 7a c9 72 42 54 cb 15 9a 67',
      );

      final pbkdf2 = Pbkdf2(
        macAlgorithm: macAlgorithm,
        bits: bits,
        iterations: iterations,
      );
      final actual = pbkdf2.deriveBitsSync(
        input,
        nonce: nonce,
      );
      expect(
        hexFromBytes(actual),
        hexFromBytes(expected),
      );
    });

    test('deriveBits(...): Hmac(sha384)', () async {
      final macAlgorithm = Hmac(sha512);
      final input = <int>[1, 2];
      final nonce = Nonce([3, 4]);
      final bits = 128;
      final iterations = 3;
      final expected = hexToBytes(
        'c9 70 19 df 29 5a 18 e9 c4 39 63 76 d3 c9 4d 96',
      );

      final pbkdf2 = Pbkdf2(
        macAlgorithm: macAlgorithm,
        bits: bits,
        iterations: iterations,
      );
      final actual = await pbkdf2.deriveBits(
        input,
        nonce: nonce,
      );
      expect(
        hexFromBytes(actual),
        hexFromBytes(expected),
      );
    });

    test('deriveBits(...): Hmac(sha512)', () async {
      final macAlgorithm = Hmac(sha512);
      final input = <int>[1, 2];
      final nonce = Nonce([3, 4]);
      final bits = 128;
      final iterations = 3;
      final expected = hexToBytes(
        'c9 70 19 df 29 5a 18 e9 c4 39 63 76 d3 c9 4d 96',
      );

      final pbkdf2 = Pbkdf2(
        macAlgorithm: macAlgorithm,
        bits: bits,
        iterations: iterations,
      );
      final actual = await pbkdf2.deriveBits(
        input,
        nonce: nonce,
      );
      expect(
        hexFromBytes(actual),
        hexFromBytes(expected),
      );
    });
  });
}
