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
import 'package:cryptography/utils.dart';
import 'package:test/test.dart';

void main() {
  group('Chacha20:', () {
    const algorithm = chacha20;

    test('information', () {
      expect(algorithm.name, 'chacha20');
      expect(algorithm.isAuthenticated, isFalse);
      expect(algorithm.secretKeyLength, 32);
      expect(algorithm.secretKeyValidLengths, unorderedEquals({32}));
    });

    test('10 000 random inputs encrypted and decrypted', () {
      for (var i = 0; i < 10000; i++) {
        final secretKey = chacha20.newSecretKeySync();
        final nonce = chacha20.newNonce();
        final clearText = SecretKey.randomBytes(i % 127).extractSync();
        final offset = i % 123;
        final encrypted = chacha20.encryptSync(
          clearText,
          secretKey: secretKey,
          nonce: nonce,
          keyStreamIndex: offset,
        );
        final decrypted = chacha20.decryptSync(
          encrypted,
          secretKey: secretKey,
          nonce: nonce,
          keyStreamIndex: offset,
        );
        expect(decrypted, clearText);
      }
    });

    test('newSecretKeySync(): two results are not equal', () {
      final secretKey = chacha20.newSecretKeySync();
      expect(secretKey.extractSync(), hasLength(32));
      expect(secretKey, isNot(chacha20.newSecretKeySync()));
    });

    test('newNonce(): two results are not equal', () {
      final nonce = chacha20.newNonce();
      expect(nonce.bytes, hasLength(12));
      expect(nonce, isNot(chacha20.newNonce()));
    });

    group('encryptSync(...):', () {
      test("throws ArgumentError when 'secretKey' is null", () {
        expect(() {
          chacha20.encryptSync(
            <int>[],
            secretKey: null,
            nonce: chacha20.newNonce(),
          );
        }, throwsA(const TypeMatcher<ArgumentError>()));
      });

      test("throws ArgumentError when 'secretKey' has a wrong length", () {
        expect(() {
          chacha20.encryptSync(
            <int>[],
            secretKey: SecretKey(Uint8List(31)),
            nonce: chacha20.newNonce(),
          );
        }, throwsA(const TypeMatcher<ArgumentError>()));
        expect(() {
          chacha20.encryptSync(
            <int>[],
            secretKey: SecretKey(Uint8List(33)),
            nonce: chacha20.newNonce(),
          );
        }, throwsA(const TypeMatcher<ArgumentError>()));
      });

      test("throws ArgumentError when 'nonce' has a wrong length", () {
        expect(() {
          chacha20.encryptSync(
            <int>[],
            secretKey: chacha20.newSecretKeySync(),
            nonce: Nonce(Uint8List(11)),
          );
        }, throwsA(const TypeMatcher<ArgumentError>()));
        expect(() {
          chacha20.encryptSync(
            <int>[],
            secretKey: chacha20.newSecretKeySync(),
            nonce: Nonce(Uint8List(13)),
          );
        }, throwsA(const TypeMatcher<ArgumentError>()));
      });
    });

    group('decryptSync(...):', () {
      test("throws ArgumentError when 'secretKey' is null", () {
        expect(() {
          chacha20.decryptSync(
            <int>[],
            secretKey: null,
            nonce: chacha20.newNonce(),
          );
        }, throwsA(const TypeMatcher<ArgumentError>()));
      });

      test("throws ArgumentError when 'secretKey' has a wrong length", () {
        expect(() {
          chacha20.decryptSync(
            <int>[],
            secretKey: SecretKey(Uint8List(31)),
            nonce: chacha20.newNonce(),
          );
        }, throwsA(const TypeMatcher<ArgumentError>()));
        expect(() {
          chacha20.decryptSync(
            <int>[],
            secretKey: SecretKey(Uint8List(33)),
            nonce: chacha20.newNonce(),
          );
        }, throwsA(const TypeMatcher<ArgumentError>()));
      });

      test("throws ArgumentError when 'nonce' has a wrong length", () {
        expect(() {
          chacha20.decryptSync(
            <int>[],
            secretKey: chacha20.newSecretKeySync(),
            nonce: Nonce(Uint8List(11)),
          );
        }, throwsA(const TypeMatcher<ArgumentError>()));
        expect(() {
          chacha20.decryptSync(
            <int>[],
            secretKey: chacha20.newSecretKeySync(),
            nonce: Nonce(Uint8List(13)),
          );
        }, throwsA(const TypeMatcher<ArgumentError>()));
      });
    });
  });

  test('encrypt/decrypt inputs with lengths from 0 to 1000', () async {
    // 1000 'a' letters
    final clearText = Uint8List(1000);
    clearText.fillRange(0, clearText.length, 'a'.codeUnits.single);
    final secretKey = chacha20.newSecretKeySync();
    final nonce = chacha20.newNonce();

    for (var sliceEnd = 0; sliceEnd < 1000; sliceEnd++) {
      final sliceStart = sliceEnd < 129 ? 0 : sliceEnd % 129;
      final slice = Uint8List.view(
        clearText.buffer,
        sliceStart,
        sliceEnd - sliceStart,
      );

      // Encrypt
      final encrypted = chacha20.encryptSync(
        slice,
        secretKey: secretKey,
        nonce: nonce,
      );

      // Decrypt
      final decrypted = chacha20.decryptSync(
        encrypted,
        secretKey: secretKey,
        nonce: nonce,
      );

      // Test that the decrypted matches clear text.
      expect(
        decrypted,
        slice,
      );
    }
  });

  group('RFC 7539: encryption example', () {
    // -----------------------------------------------------------------------
    // The following input/output constants are copied from the RFC 7539:
    // https://tools.ietf.org/html/rfc7539
    // -----------------------------------------------------------------------

    final cleartext =
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
            .runes
            .toList();

    final secretKey = SecretKey(hexToBytes(
      '00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f',
    ));

    final nonce = Nonce(hexToBytes(
      '00:00:00:00:00:00:00:4a:00:00:00:00',
    ));

    final initialKeyStreamIndex = 64;

    final expectedCipherText = hexToBytes('''
        6e 2e 35 9a 25 68 f9 80 41 ba 07 28 dd 0d 69 81
        e9 7e 7a ec 1d 43 60 c2 0a 27 af cc fd 9f ae 0b
        f9 1b 65 c5 52 47 33 ab 8f 59 3d ab cd 62 b3 57
        16 39 d6 24 e6 51 52 ab 8f 53 0c 35 9f 08 61 d8
        07 ca 0d bf 50 0d 6a 61 56 a3 8e 08 8a 22 b6 5e
        52 bc 51 4d 16 cc f8 06 81 8c e9 1a b7 79 37 36
        5a f9 0b bf 74 a3 5b e6 b4 0b 8e ed f2 78 5e 42
        87 4d                   
      ''');

    // -----------------------------------------------------------------------
    // End of constants from RFC 7539
    // -----------------------------------------------------------------------

    test('encrypt', () async {
      expect(
        hexFromBytes(await chacha20.encrypt(
          cleartext,
          secretKey: secretKey,
          nonce: nonce,
          keyStreamIndex: initialKeyStreamIndex,
        )),
        hexFromBytes(expectedCipherText),
      );
    });

    test('encryptSync', () {
      expect(
        hexFromBytes(chacha20.encryptSync(
          cleartext,
          secretKey: secretKey,
          nonce: nonce,
          keyStreamIndex: initialKeyStreamIndex,
        )),
        hexFromBytes(expectedCipherText),
      );
    });

    test('decrypt', () async {
      expect(
        hexFromBytes(await chacha20.decrypt(
          expectedCipherText,
          secretKey: secretKey,
          nonce: nonce,
          keyStreamIndex: initialKeyStreamIndex,
        )),
        hexFromBytes(cleartext),
      );
    });

    test('decryptSync', () {
      expect(
        hexFromBytes(chacha20.decryptSync(
          expectedCipherText,
          secretKey: secretKey,
          nonce: nonce,
          keyStreamIndex: initialKeyStreamIndex,
        )),
        hexFromBytes(cleartext),
      );
    });
  });
}
