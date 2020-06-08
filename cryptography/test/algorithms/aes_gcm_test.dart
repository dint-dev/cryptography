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

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/src/utils/hex.dart';
import 'package:test/test.dart';

void main() {
  group('aesGcm', () {
    final algorithm = aesGcm;

    test('information', () {
      expect(algorithm.name, 'aesGcm');
      expect(algorithm.isAuthenticated, isTrue);
      expect(algorithm.secretKeyLength, 32);
      expect(algorithm.secretKeyValidLengths, unorderedEquals({16, 24, 32}));
      expect(algorithm.nonceLength, 12);
      expect(algorithm.nonceLengthMin, 12);
      expect(algorithm.nonceLengthMax, 16);
      expect(algorithm.supportsAad, isTrue);
    });

    test('newSecretKey()', () async {
      final secretKey = await algorithm.newSecretKey();
      expect(secretKey.extractSync().length, 32);
      expect(algorithm.newSecretKey(), isNot(secretKey));
    });

    test('newNonce', () async {
      final nonce = await algorithm.newNonce();
      expect(nonce.bytes.length, 12);
      expect(algorithm.newNonce(), isNot(nonce));
    });

    group('plainText=0 bytes, key=16 bytes, nonce=12 bytes', () {
      List<int> plainText;
      SecretKey secretKey;
      Nonce nonce;
      List<int> cipherText;

      setUp(() {
        plainText = <int>[];
        secretKey = SecretKey(List<int>.filled(16, 2));
        nonce = Nonce(List<int>.filled(12, 1));
        cipherText = hexToBytes(
          '28 8c d1 be c0 0f a9 e5 41 79 b1 a3 b4 33 62 a6',
        );
      });

      test('encrypt', () async {
        final encrypted = await algorithm.encrypt(
          plainText,
          secretKey: secretKey,
          nonce: nonce,
        );
        expect(
          hexFromBytes(encrypted),
          hexFromBytes(cipherText),
        );
      });

      test('decrypt', () async {
        final decrypted = await algorithm.decrypt(
          cipherText,
          secretKey: secretKey,
          nonce: nonce,
        );
        expect(decrypted, plainText);
      });

      test('fails to decrypt after changing the first byte', () async {
        cipherText[0] = 0xFF & (cipherText[0] + 1);
        await expectLater(
          algorithm.decrypt(
            cipherText,
            secretKey: secretKey,
            nonce: nonce,
          ),
          throwsA(isA<MacValidationException>()),
        );
      });
    });

    group('plainText=3 bytes, key=16 bytes, nonce=12 bytes:', () {
      List<int> plainText;
      SecretKey secretKey;
      Nonce nonce;
      List<int> cipherText;

      setUp(() {
        plainText = <int>[1, 2, 3];
        secretKey = SecretKey(List<int>.filled(16, 2));
        nonce = Nonce(List<int>.filled(12, 1));
        cipherText = hexToBytes(
          '16 af 4d e1 d0 08 73 62 ed 5b d0 4e fb 81 8b de'
          '21 87 4a',
        );
      });

      test('encrypt', () async {
        final encrypted = await algorithm.encrypt(
          plainText,
          secretKey: secretKey,
          nonce: nonce,
        );
        expect(
          hexFromBytes(encrypted),
          hexFromBytes(cipherText),
        );
      });

      test('decrypt', () async {
        final decrypted = await algorithm.decrypt(
          cipherText,
          secretKey: secretKey,
          nonce: nonce,
        );
        expect(decrypted, plainText);
      });

      test('fails to decrypt after changing first byte', () async {
        cipherText[0] = 0xFF & (cipherText[0] + 1);
        await expectLater(
          algorithm.decrypt(
            cipherText,
            secretKey: secretKey,
            nonce: nonce,
          ),
          throwsA(isA<MacValidationException>()),
        );
      });
    });

    group('plainText=0 bytes, key=16 bytes, nonce=16 bytes', () {
      List<int> plainText;
      SecretKey secretKey;
      Nonce nonce;
      List<int> cipherText;

      setUp(() {
        plainText = <int>[];
        secretKey = SecretKey(List<int>.filled(32, 2));
        nonce = Nonce(List<int>.filled(16, 1));
        cipherText = hexToBytes(
          '5d 74 16 b3 6a 2a 3c 98 d3 40 ba c5 6c c5 a4 49',
        );
      });

      test('encrypt', () async {
        final encrypted = await algorithm.encrypt(
          plainText,
          secretKey: secretKey,
          nonce: nonce,
        );
        expect(
          hexFromBytes(encrypted),
          hexFromBytes(cipherText),
        );
      });

      test('decrypt', () async {
        final decrypted = await algorithm.decrypt(
          cipherText,
          secretKey: secretKey,
          nonce: nonce,
        );
        expect(decrypted, plainText);
      });

      test('fails to decrypt after changing the first byte', () async {
        cipherText[0] = 0xFF & (cipherText[0] + 1);
        await expectLater(
          algorithm.decrypt(
            cipherText,
            secretKey: secretKey,
            nonce: nonce,
          ),
          throwsA(isA<MacValidationException>()),
        );
      });
    });

    group('plainText=3 bytes, key=32 bytes, nonce=16 bytes', () {
      List<int> plainText;
      SecretKey secretKey;
      Nonce nonce;
      List<int> cipherText;

      setUp(() {
        plainText = <int>[1, 2, 3];
        secretKey = SecretKey(List<int>.filled(32, 2));
        nonce = Nonce(List<int>.filled(16, 1));
        cipherText = hexToBytes(
          'a3 1b 4d 8b 08 91 c9 dd 0a f0 6b 1c d1 b3 60 40\n'
          '42 90 9f',
        );
      });

      test('encrypt', () async {
        final encrypted = await algorithm.encrypt(
          plainText,
          secretKey: secretKey,
          nonce: nonce,
        );
        expect(
          hexFromBytes(encrypted),
          hexFromBytes(cipherText),
        );
      });

      test('decrypt', () async {
        final decrypted = await algorithm.decrypt(
          cipherText,
          secretKey: secretKey,
          nonce: nonce,
        );
        expect(decrypted, plainText);
      });

      test('fails to decrypt after changing the first byte', () async {
        cipherText[0] = 0xFF & (cipherText[0] + 1);
        await expectLater(
          algorithm.decrypt(
            cipherText,
            secretKey: secretKey,
            nonce: nonce,
          ),
          throwsA(isA<MacValidationException>()),
        );
      });
    });
  });
}
