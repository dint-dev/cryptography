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
  final secretKey128 = SecretKey(List<int>.filled(16, 2));
  final secretKey256 = SecretKey(List<int>.filled(32, 2));

  group('aesCbc:', () {
    final algorithm = aesCbc;

    test('information', () {
      expect(algorithm.name, 'aesCbc');
      expect(algorithm.isAuthenticated, isFalse);
      expect(algorithm.secretKeyLength, 32);
      expect(algorithm.secretKeyValidLengths, unorderedEquals({16, 24, 32}));
      expect(algorithm.nonceLength, 16);
      expect(algorithm.supportsAad, isFalse);
    });

    test('newSecretKey()', () async {
      final secretKey = await algorithm.newSecretKey();
      expect(secretKey.extractSync().length, 32);
    });

    test('newNonce', () async {
      final secretKey = await algorithm.newNonce();
      expect(secretKey.bytes.length, 16);
    });

    test('encrypt/decrypt input lengths 0...1000', () async {
      for (var i = 0; i < 1000; i++) {
        final plainText = List<int>.filled(i, 1);
        final secretKey = secretKey128;
        final nonce = Nonce(List<int>.filled(16, 1));

        // encrypt(...)
        final encrypted = await algorithm.encrypt(
          plainText,
          secretKey: secretKey,
          nonce: nonce,
        );

        // decrypt(...)
        final decrypted = await algorithm.decrypt(
          encrypted,
          secretKey: secretKey,
          nonce: nonce,
        );
        expect(decrypted, plainText);
      }
    });

    test('128-bit key, 0 bytes', () async {
      final plainText = <int>[];
      final secretKey = secretKey128;
      final nonce = Nonce(List<int>.filled(16, 1));
      final cipherText = hexToBytes(
        'f8 f9 57 22 63 9b 89 51 82 04 86 47 2e 45 a3 e7',
      );
      expect(cipherText, hasLength(16));

      // encrypt(...)
      {
        final encrypted = await algorithm.encrypt(
          plainText,
          secretKey: secretKey,
          nonce: nonce,
        );
        expect(
          hexFromBytes(encrypted),
          hexFromBytes(cipherText),
        );
      }

      // encryptSync(...)
      {
        final encrypted = algorithm.encryptSync(
          plainText,
          secretKey: secretKey,
          nonce: nonce,
        );
        expect(
          hexFromBytes(encrypted),
          hexFromBytes(cipherText),
        );
      }

      // decrypt(...)
      {
        final decrypted = await algorithm.decrypt(
          cipherText,
          secretKey: secretKey,
          nonce: nonce,
        );
        expect(decrypted, plainText);
      }

      // decryptSync(...)
      {
        final decrypted = algorithm.decryptSync(
          cipherText,
          secretKey: secretKey,
          nonce: nonce,
        );
        expect(decrypted, plainText);
      }
    });

    group('128-bit key, 31 bytes:', () {
      final plainText = List<int>.generate(31, (i) => 1 + i);
      final secretKey = secretKey128;
      final nonce = Nonce(List<int>.filled(16, 1));
      final cipherText = hexToBytes(
        '68 4f a0 20 8c 9f 75 f3 71 b9 77 cc 4d 4f 04 4b'
        '84 9a f4 46 1f 00 e0 ac 7c 2f d2 24 1c 71 14 e8',
      );

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

      test('encryptSync', () {
        final encrypted = algorithm.encryptSync(
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

      test('decryptSync', () {
        final decrypted = algorithm.decryptSync(
          cipherText,
          secretKey: secretKey,
          nonce: nonce,
        );
        expect(decrypted, plainText);
      });
    });

    group('128-bit key, 32 bytes', () {
      final plainText = List<int>.generate(32, (i) => 1 + i);
      final secretKey = secretKey128;
      final nonce = Nonce(List<int>.filled(16, 1));
      final cipherText = hexToBytes(
        '68 4f a0 20 8c 9f 75 f3 71 b9 77 cc 4d 4f 04 4b'
        '62 11 8f 13 ae 07 60 1d 28 15 e9 cc 4c 8a b6 84'
        '31 b2 2a 1a 9d fa f2 f5 77 8c c6 28 65 51 e3 fe',
      );

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

      test('encryptSync', () {
        final encrypted = algorithm.encryptSync(
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

      test('decryptSync', () {
        final decrypted = algorithm.decryptSync(
          cipherText,
          secretKey: secretKey,
          nonce: nonce,
        );
        expect(decrypted, plainText);
      });
    });

    group('256-bit key, 3 bytes', () {
      final plainText = <int>[1, 2, 3];
      final secretKey = secretKey256;
      final nonce = Nonce(List<int>.filled(16, 1));
      final cipherText = hexToBytes(
        '45 4c 0d c4 53 02 f3 62 d2 4c 5c a0 37 ee 67 66',
      );

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

      test('encryptSync', () {
        final encrypted = algorithm.encryptSync(
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

      test('decryptSync', () {
        final decrypted = algorithm.decryptSync(
          cipherText,
          secretKey: secretKey,
          nonce: nonce,
        );
        expect(decrypted, plainText);
      });
    });
  });
}
