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

import 'package:cryptography/browser.dart';
import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart';
import 'package:cryptography/src/utils.dart';
import 'package:cryptography/src/utils/hex.dart';
import 'package:test/test.dart';

void main() {
  group('AesGcm:', () {
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
  late AesGcm algorithm;
  setUp(() {
    algorithm = AesGcm.with256bits();
  });

  test('information', () {
    expect(algorithm.macAlgorithm, AesGcm.aesGcmMac);
    expect(algorithm.macAlgorithm.supportsAad, isTrue);
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
    final clearText = [1, 2, 3];
    final secretKey = await algorithm.newSecretKey();
    final secretBox = await algorithm.encrypt(
      clearText,
      secretKey: secretKey,
    );

    // Decrypt
    final decryptedSecretBox = await algorithm.decrypt(
      secretBox,
      secretKey: secretKey,
    );
    expect(decryptedSecretBox, clearText);
  });

  test('secretKeyLength: can be 256 bits', () async {
    final algorithm = AesGcm.with256bits();
    expect(algorithm.secretKeyLength, 32);
    final secretKey = await algorithm.newSecretKey();
    final secretKeyData = await secretKey.extract();
    expect(secretKeyData.bytes, hasLength(32));
  });

  test('secretKeyLength: can be 192 bits', () async {
    final algorithm = AesGcm.with192bits();
    expect(algorithm.secretKeyLength, 24);
    final secretKey = await algorithm.newSecretKey();
    final secretKeyData = await secretKey.extract();
    expect(secretKeyData.bytes, hasLength(24));
  });

  test('secretKeyLength: can be 128 bits', () async {
    final algorithm = AesGcm.with128bits();
    expect(algorithm.secretKeyLength, 16);
    final secretKey = await algorithm.newSecretKey();
    final secretKeyData = await secretKey.extract();
    expect(secretKeyData.bytes, hasLength(16));
  });

  test('newSecretKey(): two results are not equal', () async {
    final secretKey = await algorithm.newSecretKey();
    final otherSecretKey = await algorithm.newSecretKey();
    final secretKeyData = await secretKey.extract();
    final otherSecretKeyData = await otherSecretKey.extract();
    expect(secretKeyData.bytes, isNot(otherSecretKeyData.bytes));
    expect(secretKeyData, isNot(otherSecretKeyData));
  });

  test('nonceLength: default is 12', () async {
    expect(algorithm.nonceLength, 12);
    final nonce = await algorithm.newNonce();
    expect(nonce, hasLength(12));
  });

  test('nonceLength: can be set to 8', () async {
    final algorithm = AesGcm.with256bits(nonceLength: 8);
    expect(algorithm.nonceLength, 8);
    final nonce = await algorithm.newNonce();
    expect(nonce, hasLength(8));
  });

  test('newNonce(): two results are not equal', () async {
    final nonce = await algorithm.newNonce();
    final otherNonce = await algorithm.newNonce();
    expect(nonce, isNot(otherNonce));
    expect(nonce.hashCode, isNot(otherNonce.hashCode));
  });

  group('clearText is 0 bytes, secretKey is 16 bytes, nonce is 12 bytes', () {
    late AesGcm algorithm;
    late List<int> clearText;
    late SecretKeyData secretKey;
    late List<int> nonce;
    late List<int> cipherText;
    late Mac mac;

    setUp(() {
      algorithm = AesGcm.with128bits();
      clearText = <int>[];
      secretKey = SecretKeyData(List<int>.filled(16, 2));
      nonce = List<int>.filled(12, 1);

      // Test vectors calculated with Web Cryptography API
      cipherText = hexToBytes('');
      mac = Mac(hexToBytes('28 8c d1 be c0 0f a9 e5 41 79 b1 a3 b4 33 62 a6'));
    });

    test('encrypt(...)', () async {
      final actualSecretBox = await algorithm.encrypt(
        clearText,
        secretKey: secretKey,
        nonce: nonce,
      );
      expect(
        hexFromBytes(actualSecretBox.cipherText),
        hexFromBytes(cipherText),
      );
      expect(actualSecretBox.mac, mac);
    });

    test('decrypt(...)', () async {
      final actualClearText = await algorithm.decrypt(
        SecretBox(cipherText, nonce: nonce, mac: mac),
        secretKey: secretKey,
      );
      expect(actualClearText, clearText);
    });
  });

  group('clearText is 3 bytes, secretKey is 16 bytes, nonce is 12 bytes:', () {
    late AesGcm algorithm;
    late List<int> clearText;
    late SecretKeyData secretKey;
    late List<int> nonce;
    late List<int> cipherText;
    late Mac mac;

    setUp(() {
      algorithm = AesGcm.with128bits();
      clearText = <int>[1, 2, 3];
      secretKey = SecretKeyData(List<int>.filled(16, 2));
      nonce = List<int>.filled(12, 1);

      // Test vectors calculated with Web Cryptography API
      cipherText = hexToBytes('16 af 4d');
      mac = Mac(hexToBytes('e1 d0 08 73 62 ed 5b d0 4e fb 81 8b de 21 87 4a'));
    });

    test('encrypt(...)', () async {
      final actualSecretBox = await algorithm.encrypt(
        clearText,
        secretKey: secretKey,
        nonce: nonce,
      );
      expect(
        hexFromBytes(actualSecretBox.cipherText),
        hexFromBytes(cipherText),
      );
      expect(actualSecretBox.mac, mac);
    });

    test('decrypt(...)', () async {
      final actualClearText = await algorithm.decrypt(
        SecretBox(cipherText, nonce: nonce, mac: mac),
        secretKey: secretKey,
      );
      expect(actualClearText, clearText);
    });

    test('decrypt(...) fails if the first byte is changed', () async {
      final modifiedCipherText = cipherText.toList();
      modifiedCipherText[0] ^= 0xFF;
      await expectLater(
        algorithm.decrypt(
          SecretBox(modifiedCipherText, nonce: nonce, mac: mac),
          secretKey: secretKey,
        ),
        throwsA(isA<SecretBoxAuthenticationError>()),
      );
    });
  });

  group('clearText is 0 bytes, secretKey is 16 bytes, nonce is 16 bytes:', () {
    late List<int> clearText;
    late SecretKeyData secretKey;
    late List<int> nonce;
    late List<int> cipherText;
    late Mac mac;

    setUp(() {
      clearText = <int>[];
      secretKey = SecretKeyData(List<int>.filled(32, 2));
      nonce = List<int>.filled(16, 1);

      // Test vectors calculated with Web Cryptography API
      cipherText = hexToBytes('');
      mac = Mac(hexToBytes('5d 74 16 b3 6a 2a 3c 98 d3 40 ba c5 6c c5 a4 49'));
    });

    test('encrypt(...)', () async {
      final actualSecretBox = await algorithm.encrypt(
        clearText,
        secretKey: secretKey,
        nonce: nonce,
      );
      expect(
        hexFromBytes(actualSecretBox.cipherText),
        hexFromBytes(cipherText),
      );
      expect(actualSecretBox.mac, mac);
    });

    test('decrypt(...)', () async {
      final actualClearText = await algorithm.decrypt(
        SecretBox(cipherText, nonce: nonce, mac: mac),
        secretKey: secretKey,
      );
      expect(actualClearText, clearText);
    });
  });

  group('clearText is 3 bytes, secretKey is 32 bytes, nonce is 16 bytes:', () {
    late List<int> clearText;
    late SecretKeyData secretKey;
    late List<int> nonce;
    late List<int> cipherText;
    late Mac mac;

    setUp(() {
      clearText = <int>[1, 2, 3];
      secretKey = SecretKeyData(List<int>.filled(32, 2));
      nonce = List<int>.filled(16, 1);

      // Test vectors calculated with Web Cryptography API
      cipherText = hexToBytes('a3 1b 4d');
      mac = Mac(hexToBytes('8b 08 91 c9 dd 0a f0 6b 1c d1 b3 60 40 42 90 9f'));
    });

    test('encrypt(...)', () async {
      final actualSecretBox = await algorithm.encrypt(
        clearText,
        secretKey: secretKey,
        nonce: nonce,
      );
      expect(
        hexFromBytes(actualSecretBox.cipherText),
        hexFromBytes(cipherText),
      );
      expect(actualSecretBox.mac, mac);
    });

    test('decrypt(...)', () async {
      final actualClearText = await algorithm.decrypt(
        SecretBox(cipherText, nonce: nonce, mac: mac),
        secretKey: secretKey,
      );
      expect(actualClearText, clearText);
    });

    test('decrypt(...) fails if the first byte is changed', () async {
      final modifiedCipherText = cipherText.toList();
      modifiedCipherText[0] ^= 0xFF;
      await expectLater(
        algorithm.decrypt(
          SecretBox(modifiedCipherText, nonce: nonce, mac: mac),
          secretKey: secretKey,
        ),
        throwsA(isA<SecretBoxAuthenticationError>()),
      );
    });
  });

  group(
      'different keyStreamIndex values (secretKey is 12 bytes, nonce is 16 bytes, input is 6 bytes)',
      () {
    late AesGcm algorithm;
    setUp(() {
      algorithm = AesGcm.with128bits();
    });
    final clearText = List<int>.unmodifiable(
      hexToBytes('010203040506'),
    );
    final secretKey = SecretKeyData(List<int>.unmodifiable(
      hexToBytes('02020202020202020202020202020202'),
    ));
    final nonce = List<int>.unmodifiable(
      hexToBytes('03030303030303030303030303030303'),
    );
    late SecretBox secretBox;
    late List<int> decrypted;

    Future<void> f(int keyStreamIndex) async {
      secretBox = await algorithm.encrypt(
        clearText,
        secretKey: secretKey,
        nonce: nonce,
        keyStreamIndex: keyStreamIndex,
      );
      decrypted = await algorithm.decrypt(
        secretBox,
        secretKey: secretKey,
        keyStreamIndex: keyStreamIndex,
      );
    }

    // The following test vectors were obtained from another implementation.

    test('keyStreamIndex = 0', () async {
      await f(0);
      expect(secretBox.cipherText, hexToBytes('b0374454edfe'));
      expect(decrypted, clearText);
    });

    test('keyStreamIndex = 1', () async {
      await f(1);
      expect(secretBox.cipherText, hexToBytes('344553ecfdb5'));
      expect(decrypted, clearText);
    });

    test('keyStreamIndex = 15', () async {
      await f(15);
      expect(secretBox.cipherText, hexToBytes('686a4d9f7209'));
      expect(decrypted, clearText);
    });

    test('keyStreamIndex = 16', () async {
      await f(16);
      expect(secretBox.cipherText, hexToBytes('694c98730adc'));
      expect(decrypted, clearText);
    });

    test('keyStreamIndex = 17', () async {
      await f(17);
      expect(secretBox.cipherText, hexToBytes('4f99740bdfe2'));
      expect(decrypted, clearText);
    });
  });

  test('1 000 cycles of encryption', () async {
    final algorithm = AesGcm.with128bits();
    var secretKey = SecretKeyData(List<int>.unmodifiable(
      hexToBytes('02020202020202020202020202020202'),
    ));
    var nonce = List<int>.unmodifiable(
      hexToBytes('03030303030303030303030303030303'),
    );
    final hashAlgorithm = Sha256();

    var data = List<int>.filled(2000, 1);
    for (var i = 0; i < 1000; i++) {
      // Encrypt
      final secretBox = await algorithm.encrypt(
        data,
        secretKey: secretKey,
        nonce: nonce,
      );

      // Test that decryption works
      final decryptedSecretBox = await algorithm.decrypt(
        secretBox,
        secretKey: secretKey,
      );
      expect(decryptedSecretBox, data);

      // Change data.
      // Put MAC somewhere in the data.
      data = Uint8List.fromList(secretBox.cipherText);
      data.setRange(100, 100 + 16, secretBox.mac.bytes);

      // Change size for the next round
      data = data.sublist(1);

      // Change  secret key
      secretKey =
          SecretKeyData((await hashAlgorithm.hash(data)).bytes.sublist(0, 16));

      // Change nonce
      nonce = (await hashAlgorithm.hash(secretKey.bytes)).bytes.sublist(0, 12);
    }

    final hash = await hashAlgorithm.hash(data);
    expect(
      hexFromBytes(hash.bytes),
      // The following test vector was calculated with Web Cryptography API.
      'f3 52 fb 3f a0 3d 70 25 f3 0f 48 01 eb 3a d2 85\n'
      '89 53 06 4d 8c 53 25 38 96 ca 71 c2 90 f0 3b 06',
    );
  });
}
