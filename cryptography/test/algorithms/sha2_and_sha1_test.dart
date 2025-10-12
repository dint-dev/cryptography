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

import 'package:crypto/crypto.dart' as google_crypto;
import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:cryptography_plus/dart.dart';
import 'package:cryptography_plus/src/utils.dart';
import 'package:test/test.dart';

void main() {
  group('SHA1/2 functions:', () {
    group('DartCryptography:', () {
      setUp(() {
        Cryptography.instance = DartCryptography.defaultInstance;
      });
      _main();
    });
    group('BrowserCryptography:', () {
      setUp(() {
        Cryptography.instance = BrowserCryptography.defaultInstance;
      });
      _main();
    });
  });
}

void _main() {
  const inputString = 'hello';
  final input0 = inputString.runes.toList();
  final input1 = ''.padRight(65, 'a').runes.toList();

  group('sha1:', () {
    final algorithm = Sha1();
    final expectedHash0 = hexToBytes(
      'aa f4 c6 1d dc c5 e8 a2 da be de 0f 3b 48 2c d9 ae a9 43 4d',
    );
    final expectedHash1 = hexToBytes(
      '11 65 53 26 c7 08 d7 03 19 be 26 10 e8 a5 7d 9a 5b 95 9d 3b',
    );

    test('blockLength', () {
      expect(algorithm.blockLengthInBytes, 64);
    });

    test('hashLengthInBytes', () {
      expect(algorithm.hashLengthInBytes, 20);
    });

    test('hashSync(input0)', () async {
      // Test that the expected value is correct by using another implementation
      expect(
        hexFromBytes(google_crypto.sha1.convert(input0).bytes),
        hexFromBytes(expectedHash0),
      );

      final hash = await algorithm.hash(input0);
      expect(
        hexFromBytes(hash.bytes),
        hexFromBytes(expectedHash0),
      );
    });

    test('hashSync(_): input1', () async {
      // Test that the expected value is correct by using another implementation
      expect(
        hexFromBytes(google_crypto.sha1.convert(input1).bytes),
        hexFromBytes(expectedHash1),
      );

      final hash = await algorithm.hash(input1);
      expect(
        hexFromBytes(hash.bytes),
        hexFromBytes(expectedHash1),
      );
    });
  });

  group('sha224:', () {
    late Sha224 algorithm;

    setUp(() {
      algorithm = Sha224();
    });

    final expectedHash0 = hexToBytes(
      'ea 09 ae 9c c6 76 8c 50 fc ee 90 3e d0 54 55 6e 5b fc 83 47 90 7f 12 59 8a a2 41 93',
    );
    final expectedHash1 = hexToBytes(
      'ff 87 16 f6 00 af 42 95 9d 0e fb 52 e1 f2 1b 01 bb 32 87 33 00 93 44 d5 11 c2 99 fb',
    );

    test('blockLength', () {
      expect(algorithm.blockLengthInBytes, 64);
    });

    test('hashLengthInBytes', () {
      expect(algorithm.hashLengthInBytes, 28);
    });

    test('hashSync(input0)', () async {
      // Test that the expected value is correct by using another implementation
      expect(
        hexFromBytes(google_crypto.sha224.convert(input0).bytes),
        hexFromBytes(expectedHash0),
      );

      final hash = await algorithm.hash(input0);
      expect(
        hexFromBytes(hash.bytes),
        hexFromBytes(expectedHash0),
      );
    });

    test('hashSync(_): input1', () async {
      // Test that the expected value is correct by using another implementation
      expect(
        hexFromBytes(google_crypto.sha224.convert(input1).bytes),
        hexFromBytes(expectedHash1),
      );

      final hash = await algorithm.hash(input1);
      expect(
        hexFromBytes(hash.bytes),
        hexFromBytes(expectedHash1),
      );
    });
  });

  group('sha384:', () {
    late Sha384 algorithm;

    setUp(() {
      algorithm = Sha384();
    });

    final expectedHash0 = hexToBytes(
      '59 e1 74 87 77 44 8c 69 de 6b 80 0d 7a 33 bb fb 9f f1 b4 63 e4 43 54 c3 55 3b cd b9 c6 66 fa 90 12 5a 3c 79 f9 03 97 bd f5 f6 a1 3d e8 28 68 4f',
    );

    test('blockLength', () {
      expect(algorithm.blockLengthInBytes, 128);
    });

    test('hashLengthInBytes', () {
      expect(algorithm.hashLengthInBytes, 48);
    });

    test('hashSync(_): input0', () async {
      // Test that the expected value is correct by using another implementation
      expect(
        hexFromBytes(google_crypto.sha384.convert(input0).bytes),
        hexFromBytes(expectedHash0),
      );

      final hash = await algorithm.hash(input0);
      expect(
        hexFromBytes(hash.bytes),
        hexFromBytes(expectedHash0),
      );
    });
  });

  group('sha512:', () {
    late Sha512 algorithm;

    setUp(() {
      algorithm = Sha512();
    });
    final expectedHash0 = hexToBytes(
      '9b 71 d2 24 bd 62 f3 78 5d 96 d4 6a d3 ea 3d 73 31 9b fb c2 89 0c aa da e2 df f7 25 19 67 3c a7 23 23 c3 d9 9b a5 c1 1d 7c 7a cc 6e 14 b8 c5 da 0c 46 63 47 5c 2e 5c 3a de f4 6f 73 bc de c0 43',
    );

    test('blockLength', () {
      expect(algorithm.blockLengthInBytes, 128);
    });

    test('hashLengthInBytes', () {
      expect(algorithm.hashLengthInBytes, 64);
    });

    test('hashSync(_): input0', () async {
      // Test that the expected value is correct by using another implementation
      expect(
        hexFromBytes(google_crypto.sha512.convert(input0).bytes),
        hexFromBytes(expectedHash0),
      );

      final hash = await algorithm.hash(input0);
      expect(
        hexFromBytes(hash.bytes),
        hexFromBytes(expectedHash0),
      );
    });
  });
}
