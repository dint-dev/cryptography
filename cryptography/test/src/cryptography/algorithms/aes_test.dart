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

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/src/utils/hex.dart';
import 'package:test/test.dart';
import 'dart:typed_data';

void main() {
  final nonce = Nonce(List<int>.filled(43, 1));
  final secretKey128 = SecretKey(List<int>.filled(16, 2));
  final secretKey256 = SecretKey(List<int>.filled(32, 2));

  group('aesCbc:', () {
    final algorithm = aesCbc;

    test('newSecretKey()', () async {
      final secretKey = await algorithm.newSecretKey();
      expect(secretKey.bytes.length, 32);
    });

    test('newNonce', () async {
      final secretKey = await algorithm.newNonce();
      expect(secretKey.bytes.length, 16);
    });

    group('encrypt() / decrypt():', () {
      test('128-bit key', () async {
        final clearText = <int>[1, 2, 3];
        final secretKey = secretKey128;

        // Encrypt
        final encrypted = await algorithm.encrypt(
          clearText,
          secretKey: secretKey,
          nonce: nonce,
        );
        expect(encrypted, hasLength(16));
        expect(
          hexFromBytes(encrypted),
          '74 5a 9a 93 a4 61 69 26 92 4a e7 7d 2b ba 5c 6f',
        );

        // Decrypt
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

        // Encrypt
        final encrypted = await algorithm.encrypt(
          clearText,
          secretKey: secretKey,
          nonce: nonce,
        );
        expect(encrypted, hasLength(16));
        expect(
          hexFromBytes(encrypted),
          '45 4c 0d c4 53 02 f3 62 d2 4c 5c a0 37 ee 67 66',
        );

        // Decrypt
        final decrypted = await algorithm.decrypt(
          encrypted,
          secretKey: secretKey,
          nonce: nonce,
        );
        expect(decrypted, clearText);
      });
    });
  });

  group('aesCtr:', () {
    final algorithm = aesCtr32;

    test('newSecretKey()', () async {
      final secretKey = await algorithm.newSecretKey();
      expect(secretKey.bytes.length, 32);
    });

    test('newNonce', () async {
      final secretKey = await algorithm.newNonce();
      expect(secretKey.bytes.length, 12);
    });

    group('encrypt() / decrypt():', () {
      test('128-bit key', () async {
        final clearText = <int>[1, 2, 3];
        final secretKey = secretKey128;

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

      test('256-bit key', () async {
        final clearText = <int>[1, 2, 3];
        final secretKey = secretKey256;

        // Encrypt
        final encrypted = await algorithm.encrypt(
          clearText,
          secretKey: secretKey,
          nonce: nonce,
        );
        expect(
          hexFromBytes(encrypted),
          'd2 9b 79',
        );

        // Decrypt
        final decrypted = await algorithm.decrypt(
          encrypted,
          secretKey: secretKey,
          nonce: nonce,
        );
        expect(decrypted, clearText);
      });
    });
  });

  group('aesGcm', () {
    final algorithm = aesGcm;

    test('newSecretKey()', () async {
      final secretKey = await algorithm.newSecretKey();
      expect(secretKey.bytes.length, 32);
    }, testOn: 'chrome');

    test('newNonce', () async {
      final secretKey = await algorithm.newNonce();
      expect(secretKey.bytes.length, 16);
    }, testOn: 'chrome');

    test('encryptSync() throws UnsupportedError', () {
      expect(
        () => algorithm.encryptSync(
          const [],
          secretKey: SecretKey.randomBytes(16),
          nonce: Nonce.randomBytes(16),
        ),
        throwsUnsupportedError,
      );
    });

    group('encrypt() works in browser:', () {
      test('128-bit key', () async {
        final clearText = <int>[1, 2, 3];
        final secretKey = secretKey128;

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
    }, testOn: 'chrome');
  });
}
