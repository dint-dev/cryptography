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

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/src/utils.dart';
import 'package:test/test.dart';

void main() {
  group('blake2s:', () {
    final algorithm = Blake2s();

    test('hash length', () {
      expect(algorithm.hashLengthInBytes, 32);
    });

    test('block length', () {
      expect(algorithm.blockLengthInBytes, 32);
    });

    test('sink is reinitialized correctly', () {
      final sink = algorithm.toSync().newHashSink();
      expect(sink.isClosed, isFalse);
      expect(sink.length, 0);

      for (var length = 0; length < 256; length++) {
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

    test(
      '10 000 cycles',
      () async {
        var actual = <int>[];
        for (var i = 0; i < 10000; i++) {
          actual = (await algorithm.hash(actual)).bytes;
        }

        // Obtained from a Go program
        final expected = hexToBytes(
          '64f338fcf15a4dd6273e8b8a54d27f1502ba3ac67b67c9dc15ca1f916fa6df76',
        );

        expect(
          hexFromBytes(actual),
          hexFromBytes(expected),
        );
      },
      // This can be slow...
      timeout: Timeout(const Duration(minutes: 2)),
    );

    test('10 000 cycles, different lengths', () async {
      final data = Uint8List(10000);
      for (var i = 0; i < data.length; i++) {
        data[i] = i % 256;
      }
      var previousHash = <int>[];
      for (var i = 0; i < 10000; i++) {
        final sink = algorithm.toSync().newHashSink();
        sink.add(previousHash);
        sink.add(data.sublist(0, i));
        sink.close();
        previousHash = sink.hashBytes;
      }

      // Obtained from a Go program
      final expected = hexToBytes(
        '49e37b4a7e9e2ed81d5b72f222537e58fd0a28e6b6a935818fd802fd3e1f4a36',
      );

      expect(
        hexFromBytes(previousHash),
        hexFromBytes(expected),
      );
    });

    test('test vector from RFC 7693', () async {
      // The following vector is from RFC 7693:
      // https://tools.ietf.org/html/rfc7693
      final expectedBytes = hexToBytes('''
50 8C 5E 8C 32 7C 14 E2 E1 A7 2B A3 4E EB 45 2F
37 45 8B 20 9E D6 3A 29 4D 99 9B 4C 86 67 59 82
''');
      // hash()
      {
        final hash = await algorithm.hash(utf8.encode('abc'));
        expect(
          hexFromBytes(hash.bytes),
          hexFromBytes(expectedBytes),
        );
      }

      // hashSync()
      {
        final hash = await algorithm.hash(utf8.encode('abc'));
        expect(
          hexFromBytes(hash.bytes),
          hexFromBytes(expectedBytes),
        );
      }

      // newSink()
      {
        final sink = algorithm.newHashSink();
        sink.add('a'.codeUnits);
        sink.addSlice('bc'.codeUnits, 0, 2, false);
        sink.close();
        expect(
          hexFromBytes((await sink.hash()).bytes),
          hexFromBytes(expectedBytes),
        );
      }

      // newSink() again
      {
        final sink = algorithm.newHashSink();
        sink.add('a'.codeUnits);
        sink.add(''.codeUnits);
        sink.addSlice('b'.codeUnits, 0, 1, false);
        sink.addSlice('c'.codeUnits, 0, 1, true);
        expect(
          hexFromBytes((await sink.hash()).bytes),
          hexFromBytes(expectedBytes),
        );
      }
    });
  });
}
