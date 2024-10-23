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
  group('Blake2b:', () {
    final algorithm = Blake2b();

    test('hash length', () {
      expect(algorithm.hashLengthInBytes, 64);
    });

    test('block length', () {
      expect(algorithm.blockLengthInBytes, 64);
    });

    test('hashLengthInBytes: default is 64', () {
      expect(Blake2b().hashLengthInBytes, 64);
    });

    test('hashLengthInBytes: lengths 1..64 work', () async {
      for (var n = 1; n <= 64; n++) {
        final algorithm = Blake2b(hashLengthInBytes: n);
        expect(algorithm.hashLengthInBytes, n);
        expect(algorithm.toSync().hashLengthInBytes, n);
        await algorithm.hash([]);
        await algorithm.calculateMac([], secretKey: SecretKeyData([]));
      }
    });

    test('hashLengthInBytes: throws ArgumentError if 0', () {
      expect(() => Blake2b(hashLengthInBytes: 0), throwsArgumentError);
    });

    test('hashLengthInBytes: throws ArgumentError if 65', () {
      expect(() => Blake2b(hashLengthInBytes: 65), throwsArgumentError);
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
BA 80 A5 3F 98 1C 4D 0D 6A 27 97 B6 9F 12 F6 E9
4C 21 2F 14 68 5A C4 B7 4B 12 BB 6F DB FF A2 D1
7D 87 C5 39 2A AB 79 2D C2 52 D5 DE 45 33 CC 95
18 D3 8A A8 DB F1 92 5A B9 23 86 ED D4 00 99 23
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
    });

    test('empty input', () async {
      final expectedBytes = hexToBytes(
        '78 6a 02 f7 42 01 59 03 c6 c6 fd 85 25 52 d2 72\n'
        '91 2f 47 40 e1 58 47 61 8a 86 e2 17 f7 1f 54 19\n'
        'd2 5e 10 31 af ee 58 53 13 89 64 44 93 4e b0 4b\n'
        '90 3a 68 5b 14 48 b7 55 d5 6f 70 1a fe 9b e2 ce',
      );
      {
        final hash = await algorithm.hash(<int>[]);
        expect(
          hexFromBytes(hash.bytes),
          hexFromBytes(expectedBytes),
        );
      }
    });

    const lengths = {
      0: '786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce',
      1: '2fa3f686df876995167e7c2e5d74c4c7b6e48f8068fe0e44208344d480f7904c36963e44115fe3eb2a3ac8694c28bcb4f5a0f3276f2e79487d8219057a506e4b',
      127:
          '93cac6a4bedd751e1c145f8e76fec88fec246675898475585603bd228f883bcf4ebcc68ead8fa5f27890a243fa938bd7323ad41f9f06048a732cce2070b212c3',
      128:
          '865939e120e6805438478841afb739ae4250cf372653078a065cdcfffca4caf798e6d462b65d658fc165782640eded70963449ae1500fb0f24981d7727e22c41',
      129:
          'a60edba343e7a6933c14d203d2e535f35e6deb6c8a4f8e624c1a6f6e2612860447cb4c37e5aa11bcf03b7c3eea7228eb8b998f922794f2d1b8f2dc63f03bd3fa',
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

    test('length = 0, hashLength = 32 bytes', () async {
      final data = Uint8List(0);
      final hash = await Blake2b(hashLengthInBytes: 32).hash(data);
      expect(
        hexFromBytes(hash.bytes),
        hexFromBytes(hexToBytes(
            '0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8')),
      );
    });

    test('MAC fails if key is too large', () async {
      final key = SecretKeyData(Uint8List(65));
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
        '4d3b7ddab812a2f28acc2795d18cedbcb3704c098c65d9a6f6038cf35f9f0280fdb90b6f28890165fbcbb32e18bd13d43d1a1b4660979cee85f92aa85160004f',
      );

      expect(
        hexFromBytes(hashBytes),
        hexFromBytes(expected),
      );
    });
  });
}
