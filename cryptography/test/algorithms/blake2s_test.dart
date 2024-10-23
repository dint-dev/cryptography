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

import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:cryptography_plus/src/utils.dart';
import 'package:test/test.dart';

void main() {
  group('Blake2s:', () {
    final algorithm = Blake2s();

    test('hash length', () {
      expect(algorithm.hashLengthInBytes, 32);
    });

    test('block length', () {
      expect(algorithm.blockLengthInBytes, 32);
    });

    test('hashLengthInBytes: default is 32', () {
      expect(Blake2s().hashLengthInBytes, 32);
    });

    test('hashLengthInBytes: lengths 1..32 work', () async {
      for (var n = 1; n <= 32; n++) {
        final algorithm = Blake2s(hashLengthInBytes: n);
        expect(algorithm.hashLengthInBytes, n);
        expect(algorithm.toSync().hashLengthInBytes, n);
        await algorithm.hash([]);
        await algorithm.calculateMac([], secretKey: SecretKeyData([]));
      }
    });

    test('hashLengthInBytes: throws ArgumentError if 0', () {
      expect(() => Blake2s(hashLengthInBytes: 0), throwsArgumentError);
    });

    test('hashLengthInBytes: throws ArgumentError if 33', () {
      expect(() => Blake2s(hashLengthInBytes: 33), throwsArgumentError);
    });

    test('sink: adding after closing fails', () {
      final sink = algorithm.toSync().newHashSink();
      sink.add(const []);
      sink.close();
      expect(() => sink.add([]), throwsStateError);
    });

    test('sink: addSlice() with different cut points', () {
      final sink = algorithm.toSync().newHashSink();
      expect(sink.isClosed, isFalse);
      expect(sink.length, 0);

      for (var length = 0; length <= 256; length++) {
        final input = Uint8List(length);

        for (var cutN = 0; cutN <= algorithm.blockLengthInBytes + 1; cutN++) {
          if (cutN > length) {
            break;
          }

          sink.add(input);
          sink.close();
          expect(sink.isClosed, isTrue);
          expect(sink.length, input.length);
          expect(input, everyElement(0));
          final expectedHashBytes = Uint8List.fromList(sink.hashBytes);

          //
          // Reset
          //
          sink.reset();
          expect(sink.isClosed, isFalse);
          expect(sink.length, 0);
          expect(sink.hashBytes, isNot(expectedHashBytes));

          //
          // Hash again
          //
          sink.add(input);
          sink.close();
          expect(sink.isClosed, isTrue);
          expect(sink.length, input.length);
          expect(
            sink.hashBytes,
            expectedHashBytes,
            reason: 'length=$length',
          );

          //
          // Reset
          //
          sink.reset();
          expect(sink.isClosed, isFalse);
          expect(sink.length, 0);
          expect(sink.hashBytes, isNot(expectedHashBytes));

          //
          // Hash in two slices:
          //
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
            expectedHashBytes,
            reason: 'length=$length',
          );

          //
          // Reset
          //
          sink.reset();
          expect(sink.isClosed, isFalse);
          expect(sink.length, 0);
          expect(sink.hashBytes, isNot(expectedHashBytes));
        }
      }
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

    const lengths = {
      0: '69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9',
      1: 'e34d74dbaf4ff4c6abd871cc220451d2ea2648846c7757fbaac82fe51ad64bea',
      63: 'd962856f3fcfaac80a84722012c38da68cce6b924a397d5a3db009babefdee61',
      64: 'ae09db7cd54f42b490ef09b6bc541af688e4959bb8c53f359a6f56e38ab454a3',
      65: '857328bf990b00922782d3e81c6054c25d3375d386c7424abe3e01d79041046c',
    };

    lengths.forEach((n, expectedHex) {
      test('length = $n', () async {
        final data = Uint8List(n);
        final hash = await algorithm.hash(data);
        expect(
          hexFromBytes(hash.bytes),
          hexFromBytes(hexToBytes(expectedHex)),
        );
      });
    });

    test('length = 0, hashLength = 16 bytes', () async {
      final data = Uint8List(0);
      final hash = await Blake2b(hashLengthInBytes: 16).hash(data);
      expect(
        hexFromBytes(hash.bytes),
        hexFromBytes(hexToBytes(
          'ca e6 69 41 d9 ef bd 40 4e 4d 88 75 8e a6 76 70',
        )),
      );
    });

    test('MAC fails if key is too large', () async {
      final key = SecretKeyData(Uint8List(64));
      expect(
        () => algorithm.calculateMac([], secretKey: key),
        throwsArgumentError,
      );
    });

    test('10k cycles, each with a different length', () async {
      const n = 10 * 1000;
      final data = Uint8List(n);

      var hashBytes = <int>[];
      for (var i = 0; i < data.length; i++) {
        final hash = await algorithm.hash(data.sublist(0, i));
        hashBytes = hash.bytes;

        // XOR data with the hash.
        // Thus input for the next hash will be a function of the previous hash.
        for (var i = 0; i < data.length; i++) {
          data[i] ^= hashBytes[i % hashBytes.length];
        }
      }

      // Obtained from a Go program
      final expected = hexToBytes(
        '2f55bc4c39ee8a45bd752f4335ebf648a4fb81da47a87fb60015537cd64d98de',
      );

      expect(
        hexFromBytes(hashBytes),
        hexFromBytes(expected),
      );
    });
  });
}
