// Copyright 2023 Gohilla.
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

import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';

import '../cryptography_test.dart';

void testHmac() {
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

      test('sha224, calculateMac()', () async {
        final expected = hexToBytes(
          '896fb1128abbdf196832107cd49df33f'
          '47b4b1169912ba4f53684b22',
        );
        final hmac = Hmac(Sha224());
        final hash = await hmac.calculateMac(
          input,
          secretKey: secretKey,
          nonce: const <int>[],
        );
        expect(
          hexFromBytes(hash.bytes),
          hexFromBytes(expected),
        );
        expect(
          await hmac.calculateMac(
            input,
            secretKey: secretKey,
            nonce: const <int>[],
          ),
          hash,
        );
      });

      test('sha256, calculateMac()', () async {
        final expected = hexToBytes(
          'b0344c61d8db38535ca8afceaf0bf12b'
          '881dc200c9833da726e9376c2e32cff7',
        );
        final hmac = Hmac(Sha256());
        final hash = await hmac.calculateMac(
          input,
          secretKey: secretKey,
          nonce: const <int>[],
        );
        expect(
          hexFromBytes(hash.bytes),
          hexFromBytes(expected),
        );
        expect(
          await hmac.calculateMac(
            input,
            secretKey: secretKey,
            nonce: const <int>[],
          ),
          hash,
        );
      });

      test('sha256, addSlice()', () async {
        final expected = hexToBytes(
          'b0344c61d8db38535ca8afceaf0bf12b'
          '881dc200c9833da726e9376c2e32cff7',
        );
        final hmac = Hmac(Sha256());
        final sink = await hmac.newMacSink(secretKey: secretKey);
        sink.addSlice(input, 0, input.length, true);
        final hash = await sink.mac();
        expect(
          hexFromBytes(hash.bytes),
          hexFromBytes(expected),
        );
        expect(
          await hmac.calculateMac(
            input,
            secretKey: secretKey,
            nonce: const <int>[],
          ),
          hash,
        );
      });

      test('sha256, add(), close()', () async {
        final expected = hexToBytes(
          'b0344c61d8db38535ca8afceaf0bf12b'
          '881dc200c9833da726e9376c2e32cff7',
        );
        final hmac = Hmac(Sha256());
        final sink = await hmac.newMacSink(secretKey: secretKey);
        sink.add(input);
        sink.close();
        final hash = await sink.mac();
        expect(
          hexFromBytes(hash.bytes),
          hexFromBytes(expected),
        );
        expect(
          await hmac.calculateMac(
            input,
            secretKey: secretKey,
            nonce: const <int>[],
          ),
          hash,
        );
      });

      test('sha384, calculateMac()', () async {
        final expected = hexToBytes(
          'afd03944d84895626b0825f4ab46907f'
          '15f9dadbe4101ec682aa034c7cebc59c'
          'faea9ea9076ede7f4af152e8b2fa9cb6',
        );
        final hmac = Hmac(Sha384());
        final hash = await hmac.calculateMac(
          input,
          secretKey: secretKey,
          nonce: const <int>[],
        );
        expect(
          hexFromBytes(hash.bytes),
          hexFromBytes(expected),
        );
      });

      test('sha512, calculateMac()', () async {
        final expected = hexToBytes(
          '87aa7cdea5ef619d4ff0b4241a1d6cb0'
          '2379f4e2ce4ec2787ad0b30545e17cde'
          'daa833b7d6b8a702038b274eaea3f4e4'
          'be9d914eeb61f1702e696c203a126854',
        );
        final hmac = Hmac(Sha512());
        final hash = await hmac.calculateMac(
          input,
          secretKey: secretKey,
          nonce: const <int>[],
        );
        expect(
          hexFromBytes(hash.bytes),
          hexFromBytes(expected),
        );
      });
    });
  });
}
