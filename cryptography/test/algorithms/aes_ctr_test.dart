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

import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:cryptography_plus/dart.dart';
import 'package:cryptography_plus/src/_internal/hex.dart';
import 'package:test/test.dart';

void main() {
  group('AesCtr:', () {
    group('DartCryptography:', () {
      setUp(() {
        Cryptography.instance = DartCryptography.defaultInstance;
      });
      _main();
    });
    group('BrowserCryptography:', () {
      setUp(() {
        Cryptography.instance = BrowserCryptography.defaultInstance;
      });
      _main();
    });
  });
}

void _main() {
  late AesCtr algorithm;
  late String prefix;
  setUp(() {
    algorithm = AesCtr.with256bits(macAlgorithm: Hmac.sha256());
    final isBrowser = Cryptography.instance is BrowserCryptography;
    prefix = isBrowser ? 'Browser' : 'Dart';
  });

  test('== / hashCode', () {
    final clone = AesCtr.with256bits(
      macAlgorithm: Hmac.sha256(),
    );
    final other0 = AesCtr.with128bits(
      macAlgorithm: Hmac.sha256(),
    );
    final other1 = AesCtr.with256bits(
      macAlgorithm: Hmac.sha512(),
    );
    final other2 = AesCbc.with256bits(
      macAlgorithm: Hmac.sha256(),
    );
    expect(algorithm, clone);
    expect(algorithm, isNot(other0));
    expect(algorithm, isNot(other1));
    expect(algorithm, isNot(other2));
    expect(algorithm.hashCode, clone.hashCode);
    expect(algorithm.hashCode, isNot(other0.hashCode));
    expect(algorithm.hashCode, isNot(other1.hashCode));
    expect(algorithm.hashCode, isNot(other2.hashCode));
  });

  test('information: 128 bits', () {
    final algorithm = AesCtr.with128bits(macAlgorithm: Hmac.sha256());
    expect(algorithm.macAlgorithm, Hmac.sha256());
    expect(algorithm.secretKeyLength, 16);
    expect(algorithm.nonceLength, 16);
    expect(
      algorithm.toString(),
      '${prefix}AesCtr.with128bits(macAlgorithm: ${prefix}Hmac.sha256(), counterBits: 64)',
    );
  });

  test('information: 192 bits', () {
    final algorithm = AesCtr.with192bits(macAlgorithm: Hmac.sha256());
    expect(algorithm.macAlgorithm, Hmac.sha256());
    expect(algorithm.secretKeyLength, 24);
    expect(algorithm.nonceLength, 16);

    // Web Cryptography does not support 192-bit keys
    expect(
      algorithm.toString(),
      'DartAesCtr.with192bits(macAlgorithm: ${prefix}Hmac.sha256(), counterBits: 64)',
    );
  });

  test('information: 256 bits', () {
    expect(algorithm.macAlgorithm, Hmac.sha256());
    expect(algorithm.secretKeyLength, 32);
    expect(algorithm.nonceLength, 16);
    expect(
      algorithm.toString(),
      '${prefix}AesCtr.with256bits(macAlgorithm: ${prefix}Hmac.sha256(), counterBits: 64)',
    );
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

  test('newSecretKey(): length is 32', () async {
    final secretKey = await algorithm.newSecretKey();
    final secretKeyData = await secretKey.extract();
    expect(secretKeyData.bytes, hasLength(32));
  });

  test('newSecretKey(): two results are not equal', () async {
    final secretKey = await algorithm.newSecretKey();
    final secretKeyData = await secretKey.extract();

    final otherSecretKey = await algorithm.newSecretKey();
    final otherSecretKeyData = await otherSecretKey.extract();

    expect(secretKeyData.bytes, isNot(otherSecretKeyData.bytes));
    expect(secretKeyData, isNot(otherSecretKeyData));
  });

  test('newNonce(): length is 16', () async {
    final nonce = algorithm.newNonce();
    expect(nonce, hasLength(16));
  });

  test('newNonce(): two results are not equal', () async {
    final nonce = algorithm.newNonce();
    final otherNonce = algorithm.newNonce();
    expect(nonce, isNot(otherNonce));
    expect(nonce, isNot(otherNonce));
    expect(nonce.hashCode, isNot(otherNonce.hashCode));
  });

  group('encrypt() / decrypt():', () {
    test('encrypt/decrypt input lengths 0...1000', () async {
      for (var length = 0; length < 1000; length++) {
        final clearText = List<int>.filled(length, 1);
        final secretKey = SecretKey(List<int>.filled(32, 2));
        final nonce = List<int>.filled(16, 1);

        // encrypt(...)
        final secretBox = await algorithm.encrypt(
          clearText,
          secretKey: secretKey,
          nonce: nonce,
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

        // decrypt(...)
        final decrypted0 = await algorithm.decrypt(
          secretBox,
          secretKey: secretKey,
        );
        expect(decrypted0, clearText);
      }
    });

    test('encrypt/decrypt input lengths 256...1000, keyStreamIndex=1 or 17',
        () async {
      for (var length = 256; length < 1000; length++) {
        final clearText = List<int>.unmodifiable(List<int>.filled(length, 1));
        final secretKey = await algorithm.newSecretKey();
        final nonce = List<int>.unmodifiable(List<int>.filled(16, 1));

        // encrypt(...) with keyStreamIndex:1
        final encrypted1 = await algorithm.encrypt(
          clearText,
          secretKey: secretKey,
          nonce: nonce,
          keyStreamIndex: 1,
        );

        // decrypt(...) with keyStreamIndex:1
        final decrypted1 = await algorithm.decrypt(
          encrypted1,
          secretKey: secretKey,
          keyStreamIndex: 1,
        );
        expect(decrypted1, clearText);

        // encrypt(...) with keyStreamIndex:17
        final encrypted2 = await algorithm.encrypt(
          clearText,
          secretKey: secretKey,
          nonce: nonce,
          keyStreamIndex: 17,
        );
        expect(encrypted2, isNot(encrypted1));

        // decrypt(...) with keyStreamIndex:17
        final decrypted2 = await algorithm.decrypt(
          encrypted2,
          secretKey: secretKey,
          keyStreamIndex: 17,
        );
        expect(decrypted2, clearText);
      }
    });

    group('128-bit key, 12 byte nonce, 0 byte message', () {
      late AesCtr algorithm;
      final clearText = <int>[];
      final secretKey = SecretKey(List<int>.filled(16, 2));
      final nonce = List<int>.filled(12, 1);
      final cipherText = Uint8List(0);

      setUp(() {
        algorithm = AesCtr.with128bits(macAlgorithm: Hmac.sha256());
      });

      test('encrypt', () async {
        final secretBox = await algorithm.encrypt(
          clearText,
          secretKey: secretKey,
          nonce: nonce,
        );
        expect(
          hexFromBytes(secretBox.cipherText),
          hexFromBytes(cipherText),
        );
      });

      test('decrypt', () async {
        final mac = await Hmac.sha256().calculateMac(
          cipherText,
          secretKey: secretKey,
        );
        final secretBox = SecretBox(
          cipherText,
          nonce: nonce,
          mac: mac,
        );
        final actualClearText = await algorithm.decrypt(
          secretBox,
          secretKey: secretKey,
        );
        expect(actualClearText, clearText);
      });
    });

    group('128-bit key, 12 byte nonce, 3 byte message', () {
      late AesCtr algorithm;
      final clearText = <int>[1, 2, 3];
      final secretKey = SecretKey(List<int>.filled(16, 2));
      final nonce = List<int>.filled(12, 1);
      final cipherText = hexToBytes(
        '38 1f 47',
      );

      setUp(() {
        algorithm = AesCtr.with128bits(macAlgorithm: Hmac.sha256());
      });

      test('encrypt', () async {
        final secretBox = await algorithm.encrypt(
          clearText,
          secretKey: secretKey,
          nonce: nonce,
        );
        expect(
          hexFromBytes(secretBox.cipherText),
          hexFromBytes(cipherText),
        );
      });

      test('decrypt', () async {
        final mac = await Hmac.sha256().calculateMac(
          cipherText,
          secretKey: secretKey,
        );
        final secretBox = SecretBox(
          cipherText,
          nonce: nonce,
          mac: mac,
        );
        final actualClearText = await algorithm.decrypt(
          secretBox,
          secretKey: secretKey,
        );
        expect(actualClearText, clearText);
      });
    });

    group('128-bit key, 16 byte nonce, 33 byte message', () {
      late AesCtr algorithm;
      final clearText = List<int>.generate(33, (i) => 1 + i);
      final secretKey = SecretKey(List<int>.filled(16, 2));
      final nonce = List<int>.filled(16, 1);
      final cipherText = hexToBytes(
        '8e 40 c1 4f eb 68 64 4f 22 1c 51 a5 4c 3f 20 6c'
        'c9 c7 4f 85 32 8b 36 66 ea 4f 32 b4 81 e3 bf 67'
        '77',
      );

      setUp(() {
        algorithm = AesCtr.with128bits(macAlgorithm: Hmac.sha256());
      });

      test('encrypt', () async {
        final secretBox = await algorithm.encrypt(
          clearText,
          secretKey: secretKey,
          nonce: nonce,
        );
        expect(
          hexFromBytes(secretBox.cipherText),
          hexFromBytes(cipherText),
        );
      });

      test('decrypt', () async {
        final mac = await Hmac.sha256().calculateMac(
          cipherText,
          secretKey: secretKey,
        );
        final secretBox = SecretBox(
          cipherText,
          nonce: nonce,
          mac: mac,
        );
        final actualClearText = await algorithm.decrypt(
          secretBox,
          secretKey: secretKey,
        );
        expect(actualClearText, clearText);
      });
    });

    group('192-bit key, 16 byte nonce, 33 byte message', () {
      late AesCtr algorithm;
      final clearText = List<int>.generate(33, (i) => 1 + i);
      final secretKey = SecretKey(List<int>.generate(24, (i) => 100 + i));
      final nonce = List<int>.filled(16, 1);
      final cipherText = hexToBytes(
        '5c 8b 11 d7 6b 85 b7 e5 9f 5e 95 fb c9 b7 f5 79\n'
        '99 6b 55 6e b0 3b 3e 0e 8a 6d 6c 79 bb 57 86 8f\n'
        '53',
      );

      setUp(() {
        algorithm = AesCtr.with192bits(macAlgorithm: Hmac.sha256());
      });

      test('encrypt', () async {
        final secretBox = await algorithm.encrypt(
          clearText,
          secretKey: secretKey,
          nonce: nonce,
        );
        expect(
          hexFromBytes(secretBox.cipherText),
          hexFromBytes(cipherText),
        );
      });

      test('decrypt', () async {
        final mac = await Hmac.sha256().calculateMac(
          cipherText,
          secretKey: secretKey,
        );
        final secretBox = SecretBox(
          cipherText,
          nonce: nonce,
          mac: mac,
        );
        final actualClearText = await algorithm.decrypt(
          secretBox,
          secretKey: secretKey,
        );
        expect(actualClearText, clearText);
      });
    });

    group('256-bit key, 12 byte nonce, 3 byte message', () {
      late AesCtr algorithm;
      final clearText = <int>[1, 2, 3];
      final secretKey = SecretKey(List<int>.filled(32, 2));
      final nonce = List<int>.filled(12, 1);
      final cipherText = hexToBytes(
        'd2 9b 79',
      );

      setUp(() {
        algorithm = AesCtr.with256bits(macAlgorithm: Hmac.sha256());
      });

      test('encrypt', () async {
        final encrypted = await algorithm.encrypt(
          clearText,
          secretKey: secretKey,
          nonce: nonce,
        );
        expect(
          hexFromBytes(encrypted.cipherText),
          hexFromBytes(cipherText),
        );
      });

      test('decrypt', () async {
        final mac = await Hmac.sha256().calculateMac(
          cipherText,
          secretKey: secretKey,
        );
        final secretBox = SecretBox(
          cipherText,
          nonce: nonce,
          mac: mac,
        );
        final decrypted = await algorithm.decrypt(
          secretBox,
          secretKey: secretKey,
        );
        expect(decrypted, clearText);
      });
    });
  });
}
