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
  group('blake2b', () {
    final algorithm = Blake2b();

    test('hash length', () {
      expect(algorithm.hashLengthInBytes, 64);
    });

    test('block length', () {
      expect(algorithm.blockLengthInBytes, 64);
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
    test('63 bytes input', () async {
      final expectedBytes = hexToBytes(
          '058460852577e7de15323b6dbfc3656b325dc67a608fa555cfd7694b64a3433d3088eb9572fca9b7e776801bf032f84e179dbec34361f5edb47128d0cf236459');
      // hash()
      {
        final hash = await algorithm.hash(utf8.encode(
            'Lorem ipsum dolor sit amet, consectetur adipiscing elit turpis.'));
        expect(
          hexFromBytes(hash.bytes),
          hexFromBytes(expectedBytes),
        );
      }
    });
    test('64 bytes input', () async {
      final expectedBytes = hexToBytes(
          'fc32fd5f4a3c6859cb6779cb14b277dd8483ae6da7fb593b62c4387a3dfe0f22fe96592b1affc725c2fd37f8d09ed5d096af377bf3b2453746d4fa79906d3221');
      // hash()
      {
        final hash = await algorithm.hash(utf8.encode(
            'Lorem ipsum dolor sit amet, consectetur adipiscing elit aliquam.'));
        expect(
          hexFromBytes(hash.bytes),
          hexFromBytes(expectedBytes),
        );
      }
    });
    test('65 bytes input', () async {
      final expectedBytes = hexToBytes(
          'c8fa7cb677e3331450b508a4920338719c36709acfb09b6f6cab2dc2bbef0d292caddf6c444b0245c9dcab77c2fddaef89176acebc4e684e3caf6e853d5ac3ed');
      // hash()
      {
        final hash = await algorithm.hash(utf8.encode(
            'Lorem ipsum dolor sit amet, consectetur adipiscing elit volutpat.'));
        expect(
          hexFromBytes(hash.bytes),
          hexFromBytes(expectedBytes),
        );
      }
    });
    test('127 bytes input', () async {
      final expectedBytes = hexToBytes(
          '4b4f18b171f48aae4159ca84129d7d03bc36cd79d89157ac80e7fdc747754b361c3928ca246e925cedd5ef4712d2aa8f21b39953b724410239da00327a040a0f');
      // hash()
      {
        final hash = await algorithm.hash(utf8.encode(
            'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Mauris ullamcorper tellus risus, a dapibus sapien hendrerit eget eros.'));
        expect(
          hexFromBytes(hash.bytes),
          hexFromBytes(expectedBytes),
        );
      }
    });
    test('128 bytes input', () async {
      final expectedBytes = hexToBytes(
          '7a5164b11f34301dc9a95b06f610d4b2fa6b7ccbe51112800e6db10890319a8fcda37ec4d50ea25001cf7b493946f2403579a852e6c44c573da3eab9bf2b0a38');
      // hash()
      {
        final hash = await algorithm.hash(utf8.encode(
            'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Fusce finibus arcu dui. Fusce sed sem lectus. Cras mi massa porta ante.'));
        expect(
          hexFromBytes(hash.bytes),
          hexFromBytes(expectedBytes),
        );
      }
    });
    test('444 bytes input', () async {
      final expectedBytes = hexToBytes(
          '8c12a0cf10e32bd38c8f458f880986609895988b013b0ca6ecf76aeb3dab2bebe8123a64c9f777acfebcca240c57e2788301ce6ae3ce30d20518a2f8d4002e9c');
      // hash()
      {
        final hash = await algorithm.hash(utf8.encode(
            'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Phasellus commodo, ante id consectetur mollis, urna felis rutrum sem, nec dictum magna ligula quis nisl. Donec varius tempus pharetra. Cras auctor molestie ornare. Cras vestibulum, nibh in tempus finibus, arcu est sagittis lectus, bibendum ullamcorper dolor sapien ac turpis. Nulla a commodo purus. Integer elit ipsum, mattis a egestas et, auctor quis diam. Curabitur placerat massa nam.'));
        expect(
          hexFromBytes(hash.bytes),
          hexFromBytes(expectedBytes),
        );
      }
    });
  });
}
