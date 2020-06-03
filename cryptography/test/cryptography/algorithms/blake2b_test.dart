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

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/src/cryptography/algorithms/blake2b_impl_browser.dart'
    as impl;
import 'package:cryptography/utils.dart';
import 'package:test/test.dart';

void main() {
  group('blake2b', () {
    test('name', () {
      expect(blake2b.name, 'blake2b');
    });

    test('hash length', () {
      expect(blake2b.hashLengthInBytes, 64);
    });

    test('block length', () {
      expect(blake2b.blockLengthInBytes, 64);
    });

    group('sum in browsers:', () {
      test('low bits carried', () {
        final v = Uint32List.fromList([uint32mask, 0, 2, 0, 3, 0]);
        impl.Blake2bSink.sum(v, 0, 2, v, 4);
        expect(v, [4, 1, 2, 0, 3, 0]);
      });

      test('low bits carried, overflows', () {
        final v = Uint32List.fromList([uint32mask, uint32mask, 1, 0, 0, 0]);
        impl.Blake2bSink.sum(v, 0, 2, v, 4);
        expect(v, [0, 0, 1, 0, 0, 0]);
      });

      test('high bits carried', () {
        final v = Uint32List.fromList([0, uint32mask, 0, 2, 0, 3]);
        impl.Blake2bSink.sum(v, 0, 2, v, 4);
        expect(v, [0, 4, 0, 2, 0, 3]);
      });

      test('high bits carried, overflows', () {
        final v = Uint32List.fromList([uint32mask, uint32mask, 0, 1, 0, 0]);
        impl.Blake2bSink.sum(v, 0, 2, v, 4);
        expect(v, [uint32mask, 0, 0, 1, 0, 0]);
      });

      test('third term omitted', () {
        final v = Uint32List.fromList([1, 1, 2, 2, 5, 5]);
        impl.Blake2bSink.sum(v, 0, 2, null, null);
        expect(v, [3, 3, 2, 2, 5, 5]);
      });
    });

    group('rotate in browsers:', () {
      // In browsers, rotation is implemented with 32-bit integers.

      test('xor #1', () {
        final v = Uint32List.fromList([0, 0, 1, 2, 1, 2]);
        impl.Blake2bSink.xorAndRotate(v, 2, 4, 24);
        expect(v, [0, 0, 0, 0, 1, 2]);
      });

      test('xor #2', () {
        final v = Uint32List.fromList([0, 0, 1, 2, 4, 8]);
        impl.Blake2bSink.xorAndRotate(v, 2, 4, 63);
        expect(v, [0, 0, (1 | 4) << 1, (8 | 2) << 1, 4, 8]);
      });

      test('32: low', () {
        final v = Uint32List.fromList([0, 0, 0xF1F2F3F4, 0, 0, 0]);
        impl.Blake2bSink.xorAndRotate(v, 2, 4, 32);
        expect(v, [0, 0, 0, 0xF1F2F3F4, 0, 0]);
      });

      test('32: high', () {
        final v = Uint32List.fromList([0, 0, 0, 0xF1F2F3F4, 0, 0]);
        impl.Blake2bSink.xorAndRotate(v, 2, 4, 32);
        expect(v, [0, 0, 0xF1F2F3F4, 0, 0, 0]);
      });

      test('24: low', () {
        final v = Uint32List.fromList([0, 0, 0xF1F2F3F4, 0, 0, 0]);
        impl.Blake2bSink.xorAndRotate(v, 2, 4, 24);
        expect(v, [0, 0, 0x000000F1, 0xF2F3F400, 0, 0]);
      });

      test('24: high', () {
        final v = Uint32List.fromList([0, 0, 0, 0xF1F2F3F4, 0, 0]);
        impl.Blake2bSink.xorAndRotate(v, 2, 4, 24);
        expect(v, [0, 0, 0xF2F3F400, 0x000000F1, 0, 0]);
      });

      test('16: low', () {
        final v = Uint32List.fromList([0, 0, 0xF1F2F3F4, 0, 0, 0]);
        impl.Blake2bSink.xorAndRotate(v, 2, 4, 16);
        expect(v, [0, 0, 0x0000F1F2, 0xF3F40000, 0, 0]);
      });

      test('16: high', () {
        final v = Uint32List.fromList([0, 0, 0, 0xF1F2F3F4, 0, 0]);
        impl.Blake2bSink.xorAndRotate(v, 2, 4, 16);
        expect(v, [0, 0, 0xF3F40000, 0x0000F1F2, 0, 0]);
      });

      test('63: low', () {
        final v = Uint32List.fromList([0, 0, 0x80000001, 0, 0, 0]);
        impl.Blake2bSink.xorAndRotate(v, 2, 4, 63);
        expect(v, [0, 0, 2, 1, 0, 0]);
      });

      test('63: high', () {
        final v = Uint32List.fromList([0, 0, 0, 0x80000001, 0, 0]);
        impl.Blake2bSink.xorAndRotate(v, 2, 4, 63);
        expect(v, [0, 0, 1, 2, 0, 0]);
      });
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
        final hash = await blake2b.hash(utf8.encode('abc'));
        expect(
          hexFromBytes(hash.bytes),
          hexFromBytes(expectedBytes),
        );
      }

      // hashSync()
      {
        final hash = blake2b.hashSync(utf8.encode('abc'));
        expect(
          hexFromBytes(hash.bytes),
          hexFromBytes(expectedBytes),
        );
      }

      // newSink()
      {
        final sink = await blake2b.newSink();
        sink.add('a'.codeUnits);
        sink.addSlice('bc'.codeUnits, 0, 2, false);
        sink.close();
        expect(
          hexFromBytes(sink.hash.bytes),
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
        final hash = await blake2b.hash(<int>[]);
        expect(
          hexFromBytes(hash.bytes),
          hexFromBytes(expectedBytes),
        );
      }
    });
  });
}
