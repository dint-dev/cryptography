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

import 'package:collection/collection.dart';
import 'package:crypto/crypto.dart' as google_crypto;
import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:cryptography_plus/dart.dart';
import 'package:cryptography_plus/src/utils.dart';
import 'package:test/test.dart';

void main() {
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
  }, testOn: 'browser');
}

void _main() {
  const inputString = 'hello';
  final input0 = inputString.runes.toList();
  final input1 = ''.padRight(65, 'a').runes.toList();

  group('sha256:', () {
    late Sha256 algorithm;

    setUp(() {
      algorithm = Sha256();
    });

    final expectedHash0 = hexToBytes(
      '2c f2 4d ba 5f b0 a3 0e 26 e8 3b 2a c5 b9 e2 9e 1b 16 1e 5c 1f a7 42 5e 73 04 33 62 93 8b 98 24',
    );
    final expectedHash1 = hexToBytes(
      '63 53 61 c4 8b b9 ea b1 41 98 e7 6e a8 ab 7f 1a 41 68 5d 6a d6 2a a9 14 6d 30 1d 4f 17 eb 0a e0',
    );

    test('blockLength', () {
      expect(algorithm.blockLengthInBytes, 64);
    });

    test('hashLengthInBytes', () {
      expect(algorithm.hashLengthInBytes, 32);
    });

    test('sink is reinitialized correctly', () {
      final sink = algorithm.toSync().newHashSink();
      expect(sink.isClosed, isFalse);
      expect(sink.length, 0);

      for (var length = 0; length < 1024; length++) {
        for (var cutN = 0; cutN < 129; cutN++) {
          if (cutN > length) {
            break;
          }
          final input = Uint8List(length);

          sink.add(input);
          sink.close();
          expect(sink.isClosed, isTrue);
          expect(sink.length, input.length);
          expect(input, everyElement(0));
          final mac = Uint8List.fromList(sink.hashBytes);

          // Reset
          sink.reset();
          expect(sink.isClosed, isFalse);
          expect(sink.length, 0);
          expect(sink.hashBytes, isNot(mac));

          // Do same again
          sink.add(input);
          sink.close();
          expect(sink.isClosed, isTrue);
          expect(sink.length, input.length);
          expect(
            sink.hashBytes,
            mac,
            reason: 'length=$length',
          );

          // Reset
          sink.reset();
          expect(sink.isClosed, isFalse);
          expect(sink.length, 0);
          expect(sink.hashBytes, isNot(mac));

          // This time use:
          // addSlice(..., 0, x, false)
          // addSlice(..., x, n, true)
          final cutAt = length - cutN;
          sink.addSlice(input, 0, cutAt, false);
          expect(sink.isClosed, isFalse);
          expect(sink.length, cutAt);
          sink.addSlice(input, cutAt, input.length, true);
          expect(sink.isClosed, isTrue);
          expect(sink.length, input.length);
          expect(
            sink.hashBytes,
            mac,
            reason: 'length=$length',
          );
          expect(() => sink.add([]), throwsStateError);

          sink.reset();
          expect(sink.isClosed, isFalse);
          expect(sink.length, 0);
          expect(sink.hashBytes, isNot(mac));
        }
      }
    });

    test('hash for empty list', () async {
      final hash = await algorithm.hash(const []);
      expect(
        hexFromBytes(hash.bytes),
        'e3 b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9 24\n'
        '27 ae 41 e4 64 9b 93 4c a4 95 99 1b 78 52 b8 55',
      );
    });

    test('newSink(): try different lengths', () async {
      final data = Uint8List(500);
      for (var i = 0; i < data.length; i++) {
        data[i] = 0xFF & i;
      }

      // Try different lengths
      for (var n = 0; n < 100; n++) {
        final input = Uint8List.view(data.buffer, 0, n);
        final expectedOutput = google_crypto.sha256.convert(input).bytes;

        // We split the input into two slices.
        // We try various slices.
        for (var i in [0, 1, 31, 32, 33, 63, 64, 65]) {
          if (i > n) {
            break;
          }
          final sink = algorithm.toSync().newHashSink();
          sink.add(input.sublist(0, i));
          sink.add(input.sublist(i));
          sink.close();
          final output = sink.hashBytes;
          expect(
            hexFromBytes(output),
            hexFromBytes(expectedOutput),
            reason: 'n=$n, i=$i',
          );
        }
      }
    });

    test('newSink(): input0', () async {
      // Test that the expected value is correct by using another implementation
      expect(
        hexFromBytes(google_crypto.sha256.convert(input0).bytes),
        hexFromBytes(expectedHash0),
      );

      final sink = algorithm.newHashSink();
      sink.add([]);
      sink.add(input0.sublist(0, 0));
      sink.add(input0.sublist(0, 2));
      sink.add(input0.sublist(2));
      sink.close();
      final hash = await sink.hash();
      expect(
        hexFromBytes(hash.bytes),
        hexFromBytes(expectedHash0),
      );
    });

    test('newSink(): input1', () async {
      // Test that the expected value is correct by using another implementation
      expect(
        hexFromBytes(google_crypto.sha256.convert(input1).bytes),
        hexFromBytes(expectedHash1),
      );

      final sink = algorithm.newHashSink();
      sink.add([]);
      sink.add(input1.sublist(0, 0));
      sink.add(input1.sublist(0, 2));
      sink.add(input1.sublist(2));
      sink.close();
      final hash = await sink.hash();
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

      final hash = await algorithm.hash(input0);
      expect(
        hexFromBytes(hash.bytes),
        hexFromBytes(expectedHash0),
      );
    });

    test('hashSync(_): input0', () async {
      // Test that the expected value is correct by using another implementation
      expect(
        hexFromBytes(google_crypto.sha256.convert(input0).bytes),
        hexFromBytes(expectedHash0),
      );

      final hash = await algorithm.hash(input0);
      expect(
        hexFromBytes(hash.bytes),
        hexFromBytes(expectedHash0),
      );
    });

    test(
      'test against package:crypto',
      () {
        final random = SecureRandom.fast;
        final buffer = Uint8List(300).buffer;
        for (var j = 1; j < buffer.lengthInBytes; j++) {
          final slice = buffer.asUint8List(0, j);
          for (var i = 0; i < 3000; i++) {
            fillBytesWithSecureRandom(slice, random: random);
            final hash = algorithm.toSync().hashSync(slice).bytes;
            final packageCryptoHash = google_crypto.sha256.convert(slice).bytes;
            // Use if statement for better performance
            if (!const ListEquality().equals(hash, packageCryptoHash)) {
              expect(
                hexFromBytes(hash),
                hexFromBytes(packageCryptoHash),
              );
            }

            // One part
            {
              final sink = algorithm.toSync().newHashSink();
              sink.addSlice(slice, 0, slice.length, true);
              expect(
                sink.hashBytes,
                packageCryptoHash,
              );
            }

            // Two parts
            {
              final sink = algorithm.toSync().newHashSink();
              final c = slice.length ~/ 2;
              sink.addSlice(slice, 0, c, false);
              sink.addSlice(slice, c, slice.length, true);
              expect(
                sink.hashBytes,
                packageCryptoHash,
              );
            }

            // Three parts
            {
              final sink = algorithm.toSync().newHashSink();
              var c = slice.length ~/ 3;
              sink.addSlice(slice, 0, c, false);
              sink.addSlice(slice, c, 2 * c, false);
              sink.addSlice(slice, 2 * c, slice.length, true);
              expect(
                sink.hashBytes,
                packageCryptoHash,
              );
            }
          }
        }
      },
      testOn: 'vm',
      timeout: Timeout.factor(10),
    );
  });
}
