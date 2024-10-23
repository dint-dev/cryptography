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
  group('poly1305:', () {
    final algorithm = Poly1305();
    test('100 000 cycles', () async {
      final secretKeyBytes = Uint8List(32)
        ..[0] = 1
        ..[2] = 2;
      var k = SecretKey(secretKeyBytes);
      List<int> state = utf8.encode('Hello world');
      for (var i = 0; i < 100000; i++) {
        final mac = await algorithm.calculateMac(
          state,
          secretKey: k,
          nonce: const <int>[],
        );
        state = mac.bytes;

        // Change key to something else
        final kBytes = Uint8List(32);
        kBytes.setAll(0, state);
        kBytes.setAll(16, state);
        for (var i = 0; i < kBytes.length; i++) {
          kBytes[i] = (kBytes[i] + i) % 256;
        }
        k = SecretKey(kBytes);
      }
      expect(
        hexFromBytes(state),
        hexFromBytes(hexToBytes(
          '2b a2 02 d1 83 82 24 83 fa e2 33 8c 1c 9a 88 e3',
        )),
      );
    });

    group('Empty message', () {
      final data = hexToBytes('');
      final secretKey = SecretKey(hexToBytes(
        '85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8:01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b',
      ));
      final expectedMac = Mac(hexToBytes(
        '86 d9 3e 93 4f 63 1f 01 c7 03 49 be 81 1e fc 23',
      ));

      test('calculateMac()', () async {
        final mac = await algorithm.calculateMac(
          data,
          secretKey: secretKey,
          nonce: const <int>[],
        );
        expect(
          hexFromBytes(mac.bytes),
          hexFromBytes(expectedMac.bytes),
        );
      });

      test('add(), add(), close()', () async {
        final sink = await algorithm.newMacSink(
          secretKey: secretKey,
          nonce: const <int>[],
        );
        sink.add(const []);
        sink.add(const []);
        sink.close();
        final mac = await sink.mac();
        expect(
          hexFromBytes(mac.bytes),
          hexFromBytes(expectedMac.bytes),
        );
      });

      test('addSlice(), addSlice(), close()', () async {
        final sink = await algorithm.newMacSink(
          secretKey: secretKey,
          nonce: const <int>[],
        );
        sink.addSlice(const [], 0, 0, false);
        sink.addSlice(const [], 0, 0, true);
        final mac = await sink.mac();
        expect(
          hexFromBytes(mac.bytes),
          hexFromBytes(expectedMac.bytes),
        );
      });
    });

    group('RFC example: full message:', () {
      // -------------------------------------------------------------------------
      // The following input/output constants are copied from the RFC 7539:
      // https://tools.ietf.org/html/rfc7539
      // -------------------------------------------------------------------------
      final data = utf8.encode('Cryptographic Forum Research Group');

      final secretKey = SecretKeyData(hexToBytes(
        '85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8:01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b',
      ));

      final expectedMac = Mac(hexToBytes(
        'a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9',
      ));

      test('calculateMac()', () async {
        final mac = await algorithm.calculateMac(
          data,
          secretKey: secretKey,
          nonce: const <int>[],
        );
        expect(
          hexFromBytes(mac.bytes),
          hexFromBytes(expectedMac.bytes),
        );
      });

      test('add(), add(), close()', () async {
        final sink = await algorithm.newMacSink(
          secretKey: secretKey,
          nonce: const <int>[],
        );
        sink.add(data.sublist(0, 16));
        sink.add(data.sublist(16));
        sink.close();
        final mac = await sink.mac();
        expect(
          hexFromBytes(mac.bytes),
          hexFromBytes(expectedMac.bytes),
        );
      });

      test('addSlice(), addSlice(), close()', () async {
        final sink = await algorithm.newMacSink(
          secretKey: secretKey,
          nonce: const <int>[],
        );
        sink.addSlice(data, 0, 1, false);
        sink.addSlice(data, 1, data.length, true);
        final mac = await sink.mac();
        expect(
          hexFromBytes(mac.bytes),
          hexFromBytes(expectedMac.bytes),
        );
      });
    });

    test('RFC: additional test vector #1', () async {
      final key = Uint8List(32);
      final text = Uint8List(64);
      final tag = Uint8List(16);

      final mac = await algorithm.calculateMac(
        text,
        secretKey: SecretKeyData(key),
        nonce: const <int>[],
      );
      expect(
        hexFromBytes(mac.bytes),
        hexFromBytes(tag),
      );
    });

    group('RFC: additional test vector #2:', () {
      final key = hexToBytes('''
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e
      ''');

      final text = hexToBytes('''
      000  41 6e 79 20 73 75 62 6d 69 73 73 69 6f 6e 20 74
      016  6f 20 74 68 65 20 49 45 54 46 20 69 6e 74 65 6e
      032  64 65 64 20 62 79 20 74 68 65 20 43 6f 6e 74 72
      048  69 62 75 74 6f 72 20 66 6f 72 20 70 75 62 6c 69
      064  63 61 74 69 6f 6e 20 61 73 20 61 6c 6c 20 6f 72
      080  20 70 61 72 74 20 6f 66 20 61 6e 20 49 45 54 46
      096  20 49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 20
      112  6f 72 20 52 46 43 20 61 6e 64 20 61 6e 79 20 73
      128  74 61 74 65 6d 65 6e 74 20 6d 61 64 65 20 77 69
      144  74 68 69 6e 20 74 68 65 20 63 6f 6e 74 65 78 74
      160  20 6f 66 20 61 6e 20 49 45 54 46 20 61 63 74 69
      176  76 69 74 79 20 69 73 20 63 6f 6e 73 69 64 65 72
      192  65 64 20 61 6e 20 22 49 45 54 46 20 43 6f 6e 74
      208  72 69 62 75 74 69 6f 6e 22 2e 20 53 75 63 68 20
      224  73 74 61 74 65 6d 65 6e 74 73 20 69 6e 63 6c 75
      240  64 65 20 6f 72 61 6c 20 73 74 61 74 65 6d 65 6e
      256  74 73 20 69 6e 20 49 45 54 46 20 73 65 73 73 69
      272  6f 6e 73 2c 20 61 73 20 77 65 6c 6c 20 61 73 20
      288  77 72 69 74 74 65 6e 20 61 6e 64 20 65 6c 65 63
      304  74 72 6f 6e 69 63 20 63 6f 6d 6d 75 6e 69 63 61
      320  74 69 6f 6e 73 20 6d 61 64 65 20 61 74 20 61 6e
      336  79 20 74 69 6d 65 20 6f 72 20 70 6c 61 63 65 2c
      352  20 77 68 69 63 68 20 61 72 65 20 61 64 64 72 65
      368  73 73 65 64 20 74 6f
      ''');

      final expectedMac = Mac(hexToBytes('''
      36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e
      '''));

      test('calculateMac()', () async {
        final mac = await algorithm.calculateMac(
          text,
          secretKey: SecretKeyData(key),
          nonce: const <int>[],
        );
        expect(
          hexFromBytes(mac.bytes),
          hexFromBytes(expectedMac.bytes),
        );
      });

      test('add(), add(), close()', () async {
        final sink = await algorithm.newMacSink(
          secretKey: SecretKeyData(key),
          nonce: const <int>[],
        );
        sink.add(text.sublist(0, 16));
        sink.add(text.sublist(16));
        sink.close();
        final mac = await sink.mac();
        expect(
          hexFromBytes(mac.bytes),
          hexFromBytes(expectedMac.bytes),
        );
      });

      test('addSlice(), addSlice(), close()', () async {
        final sink = await algorithm.newMacSink(
          secretKey: SecretKeyData(key),
          nonce: const <int>[],
        );
        sink.addSlice(text, 0, 16, false);
        sink.addSlice(text, 16, text.length, true);
        final mac = await sink.mac();
        expect(
          hexFromBytes(mac.bytes),
          hexFromBytes(expectedMac.bytes),
        );
      });
    });
  });
}
