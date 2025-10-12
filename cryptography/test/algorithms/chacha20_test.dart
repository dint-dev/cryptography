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

import 'dart:typed_data';

import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:cryptography_plus/dart.dart';
import 'package:cryptography_plus/src/utils.dart';
import 'package:test/test.dart';

void main() {
  group('Chacha20:', () {
    Chacha20 algorithm = Chacha20(macAlgorithm: Hmac.sha256());

    setUp(() {
      algorithm = Chacha20(macAlgorithm: Hmac.sha256());
    });

    test('== / hashCode', () {
      final clone = Chacha20(
        macAlgorithm: Hmac.sha256(),
      );
      final other0 = Chacha20(
        macAlgorithm: Hmac.sha512(),
      );
      final other1 = DartAesCtr.with256bits(
        macAlgorithm: Hmac.sha256(),
      );
      expect(algorithm, clone);
      expect(algorithm, isNot(other0));
      expect(algorithm, isNot(other1));
      expect(algorithm.hashCode, clone.hashCode);
      expect(algorithm.hashCode, isNot(other0.hashCode));
      expect(algorithm.hashCode, isNot(other1.hashCode));
    });

    test('toString', () {
      expect(
        algorithm.toString(),
        'DartChacha20(macAlgorithm: DartHmac.sha256())',
      );
    }, testOn: 'vm');

    test('toString', () {
      expect(
        algorithm.toString(),
        'DartChacha20(macAlgorithm: BrowserHmac.sha256())',
      );
    }, testOn: 'browser');

    test('information', () {
      expect(algorithm.macAlgorithm, Hmac.sha256());
      expect(algorithm.secretKeyLength, 32);
      expect(algorithm.nonceLength, 12);
    });

    test('Checks MAC', () async {
      // Encrypt
      final secretKey = await algorithm.newSecretKey();
      final secretBox = await algorithm.encrypt(
        [1, 2, 3],
        secretKey: secretKey,
      );

      // Change MAC
      final badMac = Mac(secretBox.mac.bytes.map((e) => 0xFF ^ e).toList());
      final badSecretBox = SecretBox(
        secretBox.cipherText,
        nonce: secretBox.nonce,
        mac: badMac,
      );

      // Decrypting should fail
      await expectLater(
        algorithm.decrypt(badSecretBox, secretKey: secretKey),
        throwsA(
          isA<SecretBoxAuthenticationError>(),
        ),
      );
    });

    test('Encrypted without specifying nonce: two results are different',
        () async {
      // Encrypt
      final clearText = [1, 2, 3];
      final secretKey = await algorithm.newSecretKey();
      final secretBox = await algorithm.encrypt(
        clearText,
        secretKey: secretKey,
      );
      final otherSecretBox = await algorithm.encrypt(
        clearText,
        secretKey: secretKey,
      );
      expect(secretBox.nonce, isNot(otherSecretBox.nonce));
      expect(secretBox.cipherText, isNot(otherSecretBox.cipherText));
      expect(secretBox.mac, isNot(otherSecretBox.mac));
    });

    test('Encrypted without specifying nonce: decrypted correctly', () async {
      // Encrypt
      final clearText = [1, 2, 3];
      final secretKey = await algorithm.newSecretKey();
      final secretBox = await algorithm.encrypt(
        clearText,
        secretKey: secretKey,
      );

      // Check MAC
      final expectedMac = await Hmac.sha256().calculateMac(
        secretBox.cipherText,
        secretKey: secretKey,
        nonce: secretBox.nonce,
      );
      expect(secretBox.mac, expectedMac);

      // Decrypt
      final decryptedSecretBox = await algorithm.decrypt(
        secretBox,
        secretKey: secretKey,
      );
      expect(decryptedSecretBox, clearText);
    });

    test('random inputs encrypted and decrypted', () async {
      for (var i = 0; i < 256; i++) {
        final secretKey = await algorithm.newSecretKey();
        final nonce = algorithm.newNonce();
        final clearText = Uint8List(i % 127);
        fillBytesWithSecureRandom(clearText, random: SecureRandom.fast);
        final offset = i % 123;
        final secretBox = await algorithm.encrypt(
          clearText,
          secretKey: secretKey,
          nonce: nonce,
          keyStreamIndex: offset,
        );
        final expectedMac = await Hmac.sha256().calculateMac(
          secretBox.cipherText,
          secretKey: secretKey,
          nonce: nonce,
        );
        expect(
          hexFromBytes(secretBox.mac.bytes),
          hexFromBytes(expectedMac.bytes),
        );
        final decrypted = await algorithm.decrypt(
          secretBox,
          secretKey: secretKey,
          keyStreamIndex: offset,
        );
        expect(decrypted, clearText);
      }
    });

    test('newSecretKey(): length is 32', () async {
      final secretKey = await algorithm.newSecretKey();
      final secretKeyData = await secretKey.extract();
      expect(secretKeyData.bytes, hasLength(32));
    });

    test('newSecretKey(): two results are not equal', () async {
      final secretKey = await algorithm.newSecretKey();
      final otherSecretKey = await algorithm.newSecretKey();
      final secretKeyData = await secretKey.extract();
      final otherSecretKeyData = await otherSecretKey.extract();
      expect(secretKeyData, isNot(otherSecretKeyData));
    });

    test('newNonce(): length is ${algorithm.nonceLength}', () async {
      final nonce = algorithm.newNonce();
      expect(nonce, hasLength(algorithm.nonceLength));
    });

    test('newNonce(): two results are not equal', () async {
      final nonce = algorithm.newNonce();
      final otherNonce = algorithm.newNonce();
      expect(nonce, isNot(otherNonce));
    });

    group('encrypt(...):', () {
      test("throws ArgumentError when 'secretKey' has a wrong length",
          () async {
        await expectLater(
          algorithm.encrypt(
            <int>[],
            secretKey: SecretKey(Uint8List(31)),
          ),
          throwsA(const TypeMatcher<ArgumentError>()),
        );
        await expectLater(
          algorithm.encrypt(
            <int>[],
            secretKey: SecretKey(Uint8List(33)),
          ),
          throwsA(const TypeMatcher<ArgumentError>()),
        );
      });

      test("throws ArgumentError when 'nonce' has a wrong length", () async {
        await expectLater(
          algorithm.encrypt(
            <int>[],
            secretKey: await algorithm.newSecretKey(),
            nonce: Uint8List(11),
          ),
          throwsA(const TypeMatcher<ArgumentError>()),
        );
        await expectLater(
          algorithm.encrypt(
            <int>[],
            secretKey: await algorithm.newSecretKey(),
            nonce: Uint8List(13),
          ),
          throwsA(const TypeMatcher<ArgumentError>()),
        );
      });
    });

    group('decrypt(...):', () {
      test("throws ArgumentError when 'secretKey' has a wrong length",
          () async {
        final secretBox = await algorithm.encrypt(
          [1, 2, 3],
          secretKey: await algorithm.newSecretKey(),
        );
        await expectLater(
          algorithm.decrypt(
            secretBox,
            secretKey: SecretKey(Uint8List(31)),
          ),
          throwsArgumentError,
        );
        await expectLater(
          algorithm.decrypt(
            secretBox,
            secretKey: SecretKey(Uint8List(33)),
          ),
          throwsArgumentError,
        );
      });

      test("throws ArgumentError when 'nonce' has a wrong length", () async {
        await expectLater(
          algorithm.decrypt(
            SecretBox(<int>[], nonce: Uint8List(11), mac: Mac.empty),
            secretKey: await algorithm.newSecretKey(),
          ),
          throwsA(const TypeMatcher<ArgumentError>()),
        );
        await expectLater(
          algorithm.decrypt(
            SecretBox(<int>[], nonce: Uint8List(13), mac: Mac.empty),
            secretKey: await algorithm.newSecretKey(),
          ),
          throwsA(const TypeMatcher<ArgumentError>()),
        );
      });
    });

    test('encrypt/decrypt inputs with lengths from 0 to 1000', () async {
      // 1000 'a' letters
      final clearText = Uint8List(1000);
      clearText.fillRange(0, clearText.length, 'a'.codeUnits.single);
      final secretKey = await algorithm.newSecretKey();
      final nonce = algorithm.newNonce();

      for (var sliceEnd = 0; sliceEnd < 1000; sliceEnd++) {
        final sliceStart = sliceEnd < 129 ? 0 : sliceEnd % 129;
        final slice = Uint8List.view(
          clearText.buffer,
          sliceStart,
          sliceEnd - sliceStart,
        );

        // Encrypt
        final encrypted = await algorithm.encrypt(
          slice,
          secretKey: secretKey,
          nonce: nonce,
        );

        // Decrypt
        final decrypted = await algorithm.decrypt(
          encrypted,
          secretKey: secretKey,
        );

        // Test that the decrypted matches clear text.
        expect(
          decrypted,
          slice,
        );
      }
    }, timeout: Timeout.factor(4.0));

    group('RFC 7539: encryption example', () {
      // -----------------------------------------------------------------------
      // The following constants are from RFC 7539:
      // https://tools.ietf.org/html/rfc7539
      // -----------------------------------------------------------------------

      final cleartext =
          "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
              .runes
              .toList();

      final secretKey = SecretKey(hexToBytes(
        '00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f',
      ));

      final nonce = hexToBytes(
        '00:00:00:00:00:00:00:4a:00:00:00:00',
      );

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
        final secretBox = await algorithm.encrypt(
          cleartext,
          secretKey: secretKey,
          nonce: nonce,
          keyStreamIndex: initialKeyStreamIndex,
        );
        expect(
          hexFromBytes(secretBox.cipherText),
          hexFromBytes(expectedCipherText),
        );
      });

      test('decrypt', () async {
        final algorithm = Chacha20(macAlgorithm: MacAlgorithm.empty);
        final secretBox = SecretBox(
          expectedCipherText,
          nonce: nonce,
          mac: Mac.empty,
        );
        final decrypted = await algorithm.decrypt(
          secretBox,
          secretKey: secretKey,
          keyStreamIndex: initialKeyStreamIndex,
        );
        expect(
          hexFromBytes(decrypted),
          hexFromBytes(cleartext),
        );
      });
    });
  });
}
