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

  group('aesCtr:', () {
    final algorithm = aesCtr;

    test('information', () {
      expect(algorithm.name, 'aesCtr');
      expect(algorithm.isAuthenticated, isFalse);
      expect(algorithm.secretKeyLength, 32);
      expect(algorithm.secretKeyValidLengths, unorderedEquals({16, 24, 32}));
      expect(algorithm.nonceLength, 16);
      expect(algorithm.supportsAad, isFalse);
    });

    test('newSecretKey()', () async {
      final secretKey = await algorithm.newSecretKey();
      expect(secretKey.extractSync().length, 32);
      expect(algorithm.newSecretKey(), isNot(secretKey));
    });

    test('newNonce', () async {
      final nonce = await algorithm.newNonce();
      expect(nonce.bytes.length, 16);
      expect(algorithm.newNonce(), isNot(nonce));
    });

    group('encrypt() / decrypt():', () {
      test('encrypt/decrypt input lengths 0...1000', () async {
        for (var i = 0; i < 1000; i++) {
          final plainText = List<int>.filled(i, 1);
          final secretKey = secretKey128;
          final nonce = Nonce(List<int>.filled(16, 1));

          // encrypt(...)
          final encrypted0 = await algorithm.encrypt(
            plainText,
            secretKey: secretKey,
            nonce: nonce,
          );

          // decrypt(...)
          final decrypted0 = await algorithm.decrypt(
            encrypted0,
            secretKey: secretKey,
            nonce: nonce,
          );
          expect(decrypted0, plainText);
        }
      });

      test('encrypt/decrypt input lengths 0...1000, keyStreamIndex={1,17}',
          () async {
        for (var i = 0; i < 1000; i++) {
          if (i < 256) {
            continue;
          }
          final plainText = List<int>.filled(i, 1);
          final secretKey = secretKey128;
          final nonce = Nonce(List<int>.filled(16, 1));

          // encrypt(...) with keyStreamIndex:1
          final encrypted1 = await algorithm.encrypt(
            plainText,
            secretKey: secretKey,
            nonce: nonce,
            keyStreamIndex: 1,
          );

          // decrypt(...) with keyStreamIndex:1
          final decrypted1 = await algorithm.decrypt(
            encrypted1,
            secretKey: secretKey,
            nonce: nonce,
            keyStreamIndex: 1,
          );
          expect(decrypted1, plainText);

          // encrypt(...) with keyStreamIndex:17
          final encrypted2 = await algorithm.encrypt(
            plainText,
            secretKey: secretKey,
            nonce: nonce,
            keyStreamIndex: 17,
          );
          expect(encrypted2, isNot(encrypted1));

          // decrypt(...) with keyStreamIndex:17
          final decrypted2 = await algorithm.decrypt(
            encrypted2,
            secretKey: secretKey,
            nonce: nonce,
            keyStreamIndex: 17,
          );
          expect(decrypted2, plainText);
        }
      }, testOn: 'vm');

      group('128-bit key, 12 byte nonce, 3 byte message', () {
        final plainText = <int>[1, 2, 3];
        final secretKey = secretKey128;
        final nonce = Nonce(List<int>.filled(12, 1));
        final cipherText = hexToBytes(
          '38 1f 47',
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

        test('decrypt', () async {
          final decrypted = await algorithm.decrypt(
            cipherText,
            secretKey: secretKey,
            nonce: nonce,
          );
          expect(decrypted, plainText);
        });
      });

      group('128-bit key, 16 byte nonce, 33 byte message', () {
        // Two blocks
        final plainText = List<int>.generate(33, (i) => 1 + i);
        final secretKey = secretKey128;
        final nonce = Nonce(List<int>.filled(16, 1));
        final cipherText = hexToBytes(
          '8e 40 c1 4f eb 68 64 4f 22 1c 51 a5 4c 3f 20 6c'
          'c9 c7 4f 85 32 8b 36 66 ea 4f 32 b4 81 e3 bf 67'
          '77',
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

      group('256-bit key, 12 byte nonce, 3 byte message', () {
        final plainText = <int>[1, 2, 3];
        final secretKey = secretKey256;
        final nonce = Nonce(List<int>.filled(12, 1));
        final cipherText = hexToBytes(
          'd2 9b 79',
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
  });
}
