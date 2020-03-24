// Copyright 2019 Gohilla Ltd (https://gohilla.com).
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
import 'package:cryptography/utils.dart';
import 'package:test/test.dart';

void main() {
  group('Hmac', () {
    final hmac = Hmac(sha256);

    test('toString()', () {
      expect(Hmac(sha224).toString(), 'Hmac(sha224)');
      expect(Hmac(sha256).toString(), 'Hmac(sha256)');
    });

    test('hashAlgorithm', () {
      expect(Hmac(sha224).hashAlgorithm, same(sha224));
      expect(Hmac(sha256).hashAlgorithm, same(sha256));
    });

    test('calculateMac(...): null input', () async {
      await expectLater(
        () => hmac.calculateMac(null, secretKey: SecretKey(<int>[])),
        throwsArgumentError,
      );
    });

    test('calculateMac(...): null secretKey', () async {
      await expectLater(
        () => hmac.calculateMac(<int>[], secretKey: null),
        throwsArgumentError,
      );
    });

    test('calculateMacSync(...): null input', () {
      expect(
        () => hmac.calculateMacSync(null, secretKey: SecretKey(<int>[])),
        throwsArgumentError,
      );
    });

    test('calculateMacSync(...): null secretKey', () {
      expect(
        () => hmac.calculateMacSync(<int>[], secretKey: null),
        throwsArgumentError,
      );
    });

    test('newSink(...): null secretKey', () {
      expect(
        () => hmac.newSink(secretKey: null),
        throwsArgumentError,
      );
    });

    test('newSink(...): null input', () {
      final sink = hmac.newSink(secretKey: SecretKey(<int>[]));
      expect(() => sink.add(null), throwsArgumentError);
    });

    test('newSink(): closing twice fails', () {
      final sink = hmac.newSink(secretKey: SecretKey(<int>[]));
      sink.closeSync();
      expect(() => sink.closeSync(), throwsStateError);
    });

    group('RFC 4231:', () {
      group('test vector #1:', () {
        // "Hi There"
        final input = hexToBytes(
          '4869205468657265',
        );
        final secretKey = SecretKey(hexToBytes(
          '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'
          '0b0b0b0b',
        ));

        test('sha224', () {
          final expected = hexToBytes(
            '896fb1128abbdf196832107cd49df33f'
            '47b4b1169912ba4f53684b22',
          );
          final hash = Hmac(sha224).calculateMacSync(
            input,
            secretKey: secretKey,
          );
          expect(
            hexFromBytes(hash.bytes),
            hexFromBytes(expected),
          );
        });

        test('sha256', () {
          final expected = hexToBytes(
            'b0344c61d8db38535ca8afceaf0bf12b'
            '881dc200c9833da726e9376c2e32cff7',
          );

          expect(
            google_crypto.Hmac(google_crypto.sha256, secretKey.bytes)
                .convert(input)
                .bytes,
            expected,
          );

          final hash = Hmac(sha256).calculateMacSync(
            input,
            secretKey: secretKey,
          );
          expect(
            hexFromBytes(hash.bytes),
            hexFromBytes(expected),
          );
        });

        test('sha384', () {
          final expected = hexToBytes(
            'afd03944d84895626b0825f4ab46907f'
            '15f9dadbe4101ec682aa034c7cebc59c'
            'faea9ea9076ede7f4af152e8b2fa9cb6',
          );
          final hash = Hmac(sha384).calculateMacSync(
            input,
            secretKey: secretKey,
          );
          expect(
            hexFromBytes(hash.bytes),
            hexFromBytes(expected),
          );
        });

        test('sha512', () {
          final expected = hexToBytes(
            '87aa7cdea5ef619d4ff0b4241a1d6cb0'
            '2379f4e2ce4ec2787ad0b30545e17cde'
            'daa833b7d6b8a702038b274eaea3f4e4'
            'be9d914eeb61f1702e696c203a126854',
          );
          final hash = Hmac(sha512).calculateMacSync(
            input,
            secretKey: secretKey,
          );
          expect(
            hexFromBytes(hash.bytes),
            hexFromBytes(expected),
          );
        });
      });
    });

    test('Hmac(sha256): different secretKey/data lengths', () async {
      for (var n = 0; n < 130; n++) {
        final secretKey = SecretKey(Uint8List(n));
        final data = Uint8List(n);
        final expectedBytes =
            google_crypto.Hmac(google_crypto.sha256, secretKey.bytes)
                .convert(data)
                .bytes;

        //
        // Sync
        //
        final syncMac = hmac.calculateMacSync(
          data,
          secretKey: secretKey,
        );
        expect(
          syncMac.bytes,
          expectedBytes,
          reason: 'secretKey/data length is $n',
        );

        //
        // Async
        //
        final asyncMac = await hmac.calculateMac(
          data,
          secretKey: secretKey,
        );
        expect(
          asyncMac.bytes,
          expectedBytes,
          reason: 'secretKey/data length is $n',
        );

        //
        // Sink
        //
        if (n >= 2) {
          final sink = hmac.newSink(secretKey: secretKey);
          sink.addSlice(data, 0, 0, false);
          sink.addSlice(data, 0, 2, false);
          sink.addSlice(data, 2, data.length, false);
          expect(
            sink.closeSync().bytes,
            expectedBytes,
            reason: 'secretKey/data length is $n',
          );
        }
      }
    });

    test('Hmac(sha512): different secretKey/data lengths', () async {
      for (var n = 0; n < 130; n++) {
        final secretKey = SecretKey(Uint8List(n));
        final data = Uint8List(n);
        final expectedBytes =
            google_crypto.Hmac(google_crypto.sha512, secretKey.bytes)
                .convert(data)
                .bytes;

        final hmac = Hmac(sha512);

        //
        // Sync
        //
        final syncMac = hmac.calculateMacSync(
          data,
          secretKey: secretKey,
        );
        expect(
          syncMac.bytes,
          expectedBytes,
          reason: 'secretKey/data length is $n',
        );

        //
        // Async
        //
        final asyncMac = await hmac.calculateMac(
          data,
          secretKey: secretKey,
        );
        expect(
          await asyncMac.bytes,
          expectedBytes,
          reason: 'secretKey/data length is $n',
        );

        //
        // Sink
        //
        if (n >= 2) {
          final sink = hmac.newSink(secretKey: secretKey);
          sink.addSlice(data, 0, 0, false);
          sink.addSlice(data, 0, 2, false);
          sink.addSlice(data, 2, data.length, false);
          expect(
            sink.closeSync().bytes,
            expectedBytes,
            reason: 'secretKey/data length is $n',
          );
        }
      }
    });
  });
}
