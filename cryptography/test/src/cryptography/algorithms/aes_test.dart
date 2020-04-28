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

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/src/cryptography/algorithms/aes_impl_block_function.dart'
    as block;
import 'package:cryptography/src/utils/hex.dart';
import 'package:test/test.dart';

void main() {
  final secretKey128 = SecretKey(List<int>.filled(16, 2));
  final secretKey256 = SecretKey(List<int>.filled(32, 2));

  group('AES block function:', () {
    test('128-bit key', () {
      // Constants from AES specification by NIST:
      // https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf
      final plainText = hexToBytes(
        '00112233445566778899aabbccddeeff',
      );
      final key = hexToBytes(
        '000102030405060708090a0b0c0d0e0f',
      );
      final cipherText = hexToBytes(
        '69c4e0d86a7b0430d8cdb78070b4c55a',
      );

      final actualCipherText = Uint8List(cipherText.length);
      final actualPlainText = Uint8List(cipherText.length);

      block.aesEncryptBlock(
        actualCipherText,
        0,
        plainText,
        0,
        block.prepareEncrypt(key),
      );
      block.aesDecryptBlock(
        actualPlainText,
        0,
        cipherText,
        0,
        block.prepareDecrypt(key),
      );

      expect(
        hexFromBytes(actualCipherText),
        hexFromBytes(cipherText),
      );
      expect(
        hexFromBytes(actualPlainText),
        hexFromBytes(plainText),
      );
    });

    test('192-bit key', () {
      // Constants from AES specification by NIST:
      // https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf
      final plainText = hexToBytes(
        '00112233445566778899aabbccddeeff',
      );
      final key = hexToBytes(
        '000102030405060708090a0b0c0d0e0f1011121314151617',
      );
      final cipherText = hexToBytes(
        'dda97ca4864cdfe06eaf70a0ec0d7191',
      );

      final actualCipherText = Uint8List(cipherText.length);
      final actualPlainText = Uint8List(cipherText.length);

      block.aesEncryptBlock(
        actualCipherText,
        0,
        plainText,
        0,
        block.prepareEncrypt(key),
      );
      block.aesDecryptBlock(
        actualPlainText,
        0,
        cipherText,
        0,
        block.prepareDecrypt(key),
      );

      expect(
        hexFromBytes(actualCipherText),
        hexFromBytes(cipherText),
      );
      expect(
        hexFromBytes(actualPlainText),
        hexFromBytes(plainText),
      );
    });

    test('256-bit key', () {
      // Constants from AES specification by NIST:
      // https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf
      final plainText = hexToBytes(
        '00112233445566778899aabbccddeeff',
      );
      final key = hexToBytes(
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
      );
      final cipherText = hexToBytes(
        '8ea2b7ca516745bfeafc49904b496089',
      );
      final actualCipherText = Uint8List(cipherText.length);
      final actualPlainText = Uint8List(cipherText.length);

      block.aesEncryptBlock(
        actualCipherText,
        0,
        plainText,
        0,
        block.prepareEncrypt(key),
      );
      block.aesDecryptBlock(
        actualPlainText,
        0,
        cipherText,
        0,
        block.prepareDecrypt(key),
      );

      expect(
        hexFromBytes(actualCipherText),
        hexFromBytes(cipherText),
      );
      expect(
        hexFromBytes(actualPlainText),
        hexFromBytes(plainText),
      );
    });
  });

  group('aesCbc:', () {
    final algorithm = aesCbc;

    test('information', () {
      expect(algorithm.name, 'aesCbc');
      expect(algorithm.isAuthenticated, isFalse);
      expect(algorithm.secretKeyLength, 32);
      expect(algorithm.secretKeyValidLengths, unorderedEquals({16, 24, 32}));
      expect(algorithm.nonceLength, 16);
    });

    test('newSecretKey()', () async {
      final secretKey = await algorithm.newSecretKey();
      expect(secretKey.extractSync().length, 32);
    });

    test('newNonce', () async {
      final secretKey = await algorithm.newNonce();
      expect(secretKey.bytes.length, 16);
    });

    group('encrypt() / decrypt():', () {
      test('encrypt/decrypt input lengths 0...1000', () async {
        for (var i = 0; i < 1000; i++) {
          final clearText = List<int>.filled(i, 1);
          final secretKey = secretKey128;
          final nonce = Nonce(List<int>.filled(16, 1));

          // encrypt(...)
          final encrypted = await algorithm.encrypt(
            clearText,
            secretKey: secretKey,
            nonce: nonce,
          );

          // decrypt(...)
          final decrypted = await algorithm.decrypt(
            encrypted,
            secretKey: secretKey,
            nonce: nonce,
          );
          expect(decrypted, clearText);
        }
      });

      test('128-bit key, 0 bytes', () async {
        final clearText = <int>[];
        final secretKey = secretKey128;
        final nonce = Nonce(List<int>.filled(16, 1));
        final cipherText = hexToBytes(
          'f8 f9 57 22 63 9b 89 51 82 04 86 47 2e 45 a3 e7',
        );
        expect(cipherText, hasLength(16));

        // encrypt(...)
        {
          final encrypted = await algorithm.encrypt(
            clearText,
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
            clearText,
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
          expect(decrypted, clearText);
        }

        // decryptSync(...)
        {
          final decrypted = algorithm.decryptSync(
            cipherText,
            secretKey: secretKey,
            nonce: nonce,
          );
          expect(decrypted, clearText);
        }
      });

      test('128-bit key, 31 bytes', () async {
        final clearText = List<int>.generate(31, (i) => 1 + i);
        final secretKey = secretKey128;
        final nonce = Nonce(List<int>.filled(16, 1));
        final cipherText = hexToBytes(
          '68 4f a0 20 8c 9f 75 f3 71 b9 77 cc 4d 4f 04 4b 84 9a f4 46 1f 00 e0 ac 7c 2f d2 24 1c 71 14 e8',
        );
        expect(cipherText, hasLength(32));

        // encrypt(...)
        {
          final encrypted = await algorithm.encrypt(
            clearText,
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
            clearText,
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
          expect(decrypted, clearText);
        }

        // decryptSync(...)
        {
          final decrypted = algorithm.decryptSync(
            cipherText,
            secretKey: secretKey,
            nonce: nonce,
          );
          expect(decrypted, clearText);
        }
      });

      test('128-bit key, 32 bytes', () async {
        final clearText = List<int>.generate(32, (i) => 1 + i);
        final secretKey = secretKey128;
        final nonce = Nonce(List<int>.filled(16, 1));
        final cipherText = hexToBytes(
          '68 4f a0 20 8c 9f 75 f3 71 b9 77 cc 4d 4f 04 4b 62 11 8f 13 ae 07 60 1d 28 15 e9 cc 4c 8a b6 84 31 b2 2a 1a 9d fa f2 f5 77 8c c6 28 65 51 e3 fe',
        );
        expect(cipherText, hasLength(48));

        // encrypt(...)
        {
          final encrypted = await algorithm.encrypt(
            clearText,
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
            clearText,
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
          expect(decrypted, clearText);
        }

        // decryptSync(...)
        {
          final decrypted = algorithm.decryptSync(
            cipherText,
            secretKey: secretKey,
            nonce: nonce,
          );
          expect(decrypted, clearText);
        }
      });

      test('256-bit key, 3 bytes', () async {
        final clearText = <int>[1, 2, 3];
        final secretKey = secretKey256;
        final nonce = Nonce(List<int>.filled(16, 1));
        final cipherText = hexToBytes(
          '45 4c 0d c4 53 02 f3 62 d2 4c 5c a0 37 ee 67 66',
        );
        expect(cipherText, hasLength(16));

        // encrypt(...)
        {
          final encrypted = await algorithm.encrypt(
            clearText,
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
            clearText,
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
          expect(decrypted, clearText);
        }

        // decryptSync(...)
        {
          final decrypted = algorithm.decryptSync(
            cipherText,
            secretKey: secretKey,
            nonce: nonce,
          );
          expect(decrypted, clearText);
        }
      });
    });
  });

  group('aesCtr:', () {
    final algorithm = aesCtr;

    test('information', () {
      expect(algorithm.name, 'aesCtr');
      expect(algorithm.isAuthenticated, isFalse);
      expect(algorithm.secretKeyLength, 32);
      expect(algorithm.secretKeyValidLengths, unorderedEquals({16, 24, 32}));
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

    group('encrypt() / decrypt():', () {
      test('encrypt/decrypt input lengths 0...1000', () async {
        for (var i = 0; i < 1000; i++) {
          final clearText = List<int>.filled(i, 1);
          final secretKey = secretKey128;
          final nonce = Nonce(List<int>.filled(16, 1));

          // encrypt(...)
          final encrypted = await algorithm.encrypt(
            clearText,
            secretKey: secretKey,
            nonce: nonce,
          );

          // decrypt(...)
          final decrypted = await algorithm.decrypt(
            encrypted,
            secretKey: secretKey,
            nonce: nonce,
          );
          expect(decrypted, clearText);
        }
      });

      test('128-bit key, 12 byte nonce, 3 byte message', () async {
        final clearText = <int>[1, 2, 3];
        final secretKey = secretKey128;
        final nonce = Nonce(List<int>.filled(12, 1));

        // Encrypt
        final encrypted = await algorithm.encrypt(
          clearText,
          secretKey: secretKey,
          nonce: nonce,
        );
        expect(
          hexFromBytes(encrypted),
          '38 1f 47',
        );

        // Decrypt
        final decrypted = await algorithm.decrypt(
          encrypted,
          secretKey: secretKey,
          nonce: nonce,
        );
        expect(decrypted, clearText);
      });

      test('128-bit key, 16 byte nonce, 33 byte message', () async {
        // Two blocks
        final clearText = List<int>.generate(33, (i) => 1 + i);
        final secretKey = secretKey128;
        final nonce = Nonce(List<int>.filled(16, 1));
        final cipherText = hexToBytes(
          '8e 40 c1 4f eb 68 64 4f 22 1c 51 a5 4c 3f 20 6c c9 c7 4f 85 32 8b 36 66 ea 4f 32 b4 81 e3 bf 67 77',
        );
        expect(cipherText, hasLength(33));

        // encrypt(...)
        {
          final encrypted = await algorithm.encrypt(
            clearText,
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
            clearText,
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
          expect(decrypted, clearText);
        }

        // decryptSync(...)
        {
          final decrypted = algorithm.decryptSync(
            cipherText,
            secretKey: secretKey,
            nonce: nonce,
          );
          expect(decrypted, clearText);
        }
      });

      test('256-bit key, 12 byte nonce, 3 byte message', () async {
        final clearText = <int>[1, 2, 3];
        final secretKey = secretKey256;
        final nonce = Nonce(List<int>.filled(12, 1));
        final cipherText = hexToBytes(
          'd2 9b 79',
        );

        // encrypt(...)
        {
          final encrypted = await algorithm.encrypt(
            clearText,
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
            clearText,
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
          expect(decrypted, clearText);
        }

        // decryptSync(...)
        {
          final decrypted = algorithm.decryptSync(
            cipherText,
            secretKey: secretKey,
            nonce: nonce,
          );
          expect(decrypted, clearText);
        }
      });
    });
  });

  group('aesGcm', () {
    final algorithm = aesGcm;

    test('unavailable outside browser', () {
      expect(algorithm, isNull);
    }, testOn: 'vm');

    group('in browser:', () {
      test('information', () {
        expect(algorithm.name, 'aesGcm');
        expect(algorithm.isAuthenticated, isTrue);
        expect(algorithm.secretKeyLength, 32);
        expect(algorithm.secretKeyValidLengths, unorderedEquals({16, 24, 32}));
        expect(algorithm.nonceLength, 12);
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

      group('encrypt():', () {
        test('128-bit key', () async {
          final clearText = <int>[1, 2, 3];
          final secretKey = secretKey128;
          final nonce = Nonce(List<int>.filled(43, 1));

          //
          // Encrypt
          //
          final encrypted = await algorithm.encrypt(
            clearText,
            secretKey: secretKey,
            nonce: nonce,
          );
          expect(
            hexFromBytes(encrypted),
            'a5 32 ac 06 a2 84 7c a5 3e c9 47 b7 d5 d5 81 f8 db a1 65',
          );

          //
          // Decrypt
          //
          final decrypted = await algorithm.decrypt(
            encrypted,
            secretKey: secretKey,
            nonce: nonce,
          );
          expect(decrypted, clearText);
        });

        test('256-bit key', () async {
          final clearText = <int>[1, 2, 3];
          final secretKey = secretKey256;
          final nonce = Nonce(List<int>.filled(43, 1));

          //
          // Encrypt
          //
          final encrypted = await algorithm.encrypt(
            clearText,
            secretKey: secretKey,
            nonce: nonce,
          );
          expect(
            hexFromBytes(encrypted),
            'c0 de 6d f6 2c 2c ca c3 7e 4c 11 3e 50 ab 35 c1 f6 cb 38',
          );

          //
          // Decrypt
          //
          final decrypted = await algorithm.decrypt(
            encrypted,
            secretKey: secretKey,
            nonce: nonce,
          );
          expect(decrypted, clearText);
        });
      });
    }, testOn: 'chrome');
  });
}
