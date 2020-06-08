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

import 'dart:typed_data';

import 'package:crypto/crypto.dart' as google_crypto;
import 'package:cryptography/cryptography.dart';
import 'package:cryptography/src/utils.dart';
import 'package:test/test.dart';

void main() {
  const inputString = 'hello';
  final input0 = inputString.runes.toList();
  final input1 = ''.padRight(65, 'a').runes.toList();

  group('sha1:', () {
    const algorithm = sha1;
    final expectedHash0 = hexToBytes(
      'aa f4 c6 1d dc c5 e8 a2 da be de 0f 3b 48 2c d9 ae a9 43 4d',
    );
    final expectedHash1 = hexToBytes(
      '11 65 53 26 c7 08 d7 03 19 be 26 10 e8 a5 7d 9a 5b 95 9d 3b',
    );

    test('name', () {
      expect(algorithm.name, 'sha1');
    });

    test('blockLength', () {
      expect(algorithm.blockLengthInBytes, 64);
    });

    test('hashLengthInBytes', () {
      expect(algorithm.hashLengthInBytes, 20);
    });

    test('hashSync(input0)', () {
      // Test that the expected value is correct by using another implementation
      expect(
        hexFromBytes(google_crypto.sha1.convert(input0).bytes),
        hexFromBytes(expectedHash0),
      );

      final hash = algorithm.hashSync(input0);
      expect(
        hexFromBytes(hash.bytes),
        hexFromBytes(expectedHash0),
      );
    });

    test('hashSync(_): input1', () {
      // Test that the expected value is correct by using another implementation
      expect(
        hexFromBytes(google_crypto.sha1.convert(input1).bytes),
        hexFromBytes(expectedHash1),
      );

      final hash = algorithm.hashSync(input1);
      expect(
        hexFromBytes(hash.bytes),
        hexFromBytes(expectedHash1),
      );
    });
  });

  group('sha224:', () {
    const algorithm = sha224;
    final expectedHash0 = hexToBytes(
      'ea 09 ae 9c c6 76 8c 50 fc ee 90 3e d0 54 55 6e 5b fc 83 47 90 7f 12 59 8a a2 41 93',
    );
    final expectedHash1 = hexToBytes(
      'ff 87 16 f6 00 af 42 95 9d 0e fb 52 e1 f2 1b 01 bb 32 87 33 00 93 44 d5 11 c2 99 fb',
    );

    test('name', () {
      expect(algorithm.name, 'sha224');
    });

    test('blockLength', () {
      expect(algorithm.blockLengthInBytes, 64);
    });

    test('hashLengthInBytes', () {
      expect(algorithm.hashLengthInBytes, 28);
    });

    test('hashSync(input0)', () {
      // Test that the expected value is correct by using another implementation
      expect(
        hexFromBytes(google_crypto.sha224.convert(input0).bytes),
        hexFromBytes(expectedHash0),
      );

      final hash = algorithm.hashSync(input0);
      expect(
        hexFromBytes(hash.bytes),
        hexFromBytes(expectedHash0),
      );
    });

    test('hashSync(_): input1', () {
      // Test that the expected value is correct by using another implementation
      expect(
        hexFromBytes(google_crypto.sha224.convert(input1).bytes),
        hexFromBytes(expectedHash1),
      );

      final hash = sha224.hashSync(input1);
      expect(
        hexFromBytes(hash.bytes),
        hexFromBytes(expectedHash1),
      );
    });
  });

  group('sha256:', () {
    const algorithm = sha256;
    final expectedHash0 = hexToBytes(
      '2c f2 4d ba 5f b0 a3 0e 26 e8 3b 2a c5 b9 e2 9e 1b 16 1e 5c 1f a7 42 5e 73 04 33 62 93 8b 98 24',
    );
    final expectedHash1 = hexToBytes(
      '63 53 61 c4 8b b9 ea b1 41 98 e7 6e a8 ab 7f 1a 41 68 5d 6a d6 2a a9 14 6d 30 1d 4f 17 eb 0a e0',
    );

    test('name', () {
      expect(algorithm.name, 'sha256');
    });

    test('blockLength', () {
      expect(algorithm.blockLengthInBytes, 64);
    });

    test('hashLengthInBytes', () {
      expect(algorithm.hashLengthInBytes, 32);
    });

    test('newSink(): try different lengths', () {
      final data = Uint8List(500);
      for (var i = 0; i < data.length; i++) {
        data[i] = 0xFF & i;
      }

      // Try different lengths
      for (var n = 0; n < 500; n++) {
        final input = Uint8List.view(data.buffer, 0, n);
        final expectedOutput = google_crypto.sha256.convert(input).bytes;

        // We split the input into two slices.
        // We try various slices.
        for (var i in [0, 1, 31, 32, 33, 63, 64, 65]) {
          if (i > n) {
            break;
          }
          final sink = sha256.newSink();
          sink.add(input.sublist(0, i));
          sink.add(input.sublist(i));
          sink.close();
          final output = sink.hash.bytes;
          expect(
            hexFromBytes(output),
            hexFromBytes(expectedOutput),
            reason: 'n=$n, i=$i',
          );
        }
      }
    });

    test('newSink(): input0', () {
      // Test that the expected value is correct by using another implementation
      expect(
        hexFromBytes(google_crypto.sha256.convert(input0).bytes),
        hexFromBytes(expectedHash0),
      );

      final sink = algorithm.newSink();
      expect(() => sink.add(null), throwsArgumentError);
      sink.add([]);
      sink.add(input0.sublist(0, 0));
      sink.add(input0.sublist(0, 2));
      sink.add(input0.sublist(2));
      sink.close();
      final hash = sink.hash;
      expect(
        hexFromBytes(hash.bytes),
        hexFromBytes(expectedHash0),
      );
    });

    test('newSink(): input1', () {
      // Test that the expected value is correct by using another implementation
      expect(
        hexFromBytes(google_crypto.sha256.convert(input1).bytes),
        hexFromBytes(expectedHash1),
      );

      final sink = algorithm.newSink();
      expect(() => sink.add(null), throwsArgumentError);
      sink.add([]);
      sink.add(input1.sublist(0, 0));
      sink.add(input1.sublist(0, 2));
      sink.add(input1.sublist(2));
      sink.close();
      final hash = sink.hash;
      expect(
        hexFromBytes(hash.bytes),
        hexFromBytes(expectedHash1),
      );
    });

    test('hash(_): input0', () async {
      // Test that the expected value is correct by using another implementation
      expect(
        hexFromBytes(google_crypto.sha256.convert(input0).bytes),
        hexFromBytes(expectedHash0),
      );

      await expectLater(algorithm.hash(null), throwsArgumentError);
      final hash = await algorithm.hash(input0);
      expect(
        hexFromBytes(hash.bytes),
        hexFromBytes(expectedHash0),
      );
    });

    test('hashSync(_): input0', () {
      // Test that the expected value is correct by using another implementation
      expect(
        hexFromBytes(google_crypto.sha256.convert(input0).bytes),
        hexFromBytes(expectedHash0),
      );

      expect(() => algorithm.hashSync(null), throwsArgumentError);
      final hash = algorithm.hashSync(input0);
      expect(
        hexFromBytes(hash.bytes),
        hexFromBytes(expectedHash0),
      );
    });
  });

  group('sha384:', () {
    const algorithm = sha384;
    final expectedHash0 = hexToBytes(
      '59 e1 74 87 77 44 8c 69 de 6b 80 0d 7a 33 bb fb 9f f1 b4 63 e4 43 54 c3 55 3b cd b9 c6 66 fa 90 12 5a 3c 79 f9 03 97 bd f5 f6 a1 3d e8 28 68 4f',
    );

    test('name', () {
      expect(algorithm.name, 'sha384');
    });

    test('blockLength', () {
      expect(algorithm.blockLengthInBytes, 128);
    });

    test('hashLengthInBytes', () {
      expect(algorithm.hashLengthInBytes, 48);
    });

    test('hashSync(_): input0', () {
      // Test that the expected value is correct by using another implementation
      expect(
        hexFromBytes(google_crypto.sha384.convert(input0).bytes),
        hexFromBytes(expectedHash0),
      );

      final hash = algorithm.hashSync(input0);
      expect(
        hexFromBytes(hash.bytes),
        hexFromBytes(expectedHash0),
      );
    });
  });

  group('sha512:', () {
    const algorithm = sha512;
    final expectedHash0 = hexToBytes(
      '9b 71 d2 24 bd 62 f3 78 5d 96 d4 6a d3 ea 3d 73 31 9b fb c2 89 0c aa da e2 df f7 25 19 67 3c a7 23 23 c3 d9 9b a5 c1 1d 7c 7a cc 6e 14 b8 c5 da 0c 46 63 47 5c 2e 5c 3a de f4 6f 73 bc de c0 43',
    );

    test('name', () {
      expect(algorithm.name, 'sha512');
    });

    test('blockLength', () {
      expect(algorithm.blockLengthInBytes, 128);
    });

    test('hashLengthInBytes', () {
      expect(algorithm.hashLengthInBytes, 64);
    });

    test('hashSync(_): input0', () {
      // Test that the expected value is correct by using another implementation
      expect(
        hexFromBytes(google_crypto.sha512.convert(input0).bytes),
        hexFromBytes(expectedHash0),
      );

      final hash = algorithm.hashSync(input0);
      expect(
        hexFromBytes(hash.bytes),
        hexFromBytes(expectedHash0),
      );
    });
  });
}
