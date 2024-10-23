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

import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:cryptography_plus/dart.dart';
import 'package:cryptography_plus/src/_internal/hex.dart';
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
  late String className;
  setUp(() {
    algorithm = AesGcm.with256bits();
    final isBrowser = Cryptography.instance is BrowserCryptography;
    className = isBrowser ? 'BrowserAesGcm' : 'DartAesGcm';
  });

  test('== / hashCode', () {
    final clone = AesGcm.with256bits();
    final other0 = AesGcm.with128bits();
    final other1 = AesGcm.with192bits();
    final other2 = AesGcm.with256bits(nonceLength: 14);
    expect(algorithm, clone);
    expect(algorithm, isNot(other0));
    expect(algorithm, isNot(other1));
    expect(algorithm, isNot(other2));
    expect(algorithm.hashCode, clone.hashCode);
    expect(algorithm.hashCode, isNot(other0.hashCode));
    expect(algorithm.hashCode, isNot(other1.hashCode));
    expect(algorithm.hashCode, isNot(other2.hashCode));
  });

  test('defaultNonceLength', () {
    expect(AesGcm.defaultNonceLength, 12);
  });

  test('information: 128 bits', () {
    algorithm = AesGcm.with128bits();
    expect(algorithm.macAlgorithm, AesGcm.aesGcmMac);
    expect(algorithm.macAlgorithm.supportsAad, isTrue);
    expect(algorithm.secretKeyLength, 16);
    expect(algorithm.nonceLength, AesGcm.defaultNonceLength);
    expect(algorithm.toString(), '$className.with128bits()');
  });

  test('information: 128 bits, nonce length = 8', () {
    algorithm = AesGcm.with128bits(nonceLength: 8);
    expect(algorithm.macAlgorithm, AesGcm.aesGcmMac);
    expect(algorithm.macAlgorithm.supportsAad, isTrue);
    expect(algorithm.secretKeyLength, 16);
    expect(algorithm.nonceLength, 8);
    expect(algorithm.toString(), '$className.with128bits(nonceLength: 8)');
  });

  test('information: 192 bits', () {
    algorithm = AesGcm.with192bits();
    expect(algorithm.macAlgorithm, AesGcm.aesGcmMac);
    expect(algorithm.macAlgorithm.supportsAad, isTrue);
    expect(algorithm.secretKeyLength, 24);
    expect(algorithm.nonceLength, AesGcm.defaultNonceLength);

    // Web Cryptography does not support 192-bit keys
    expect(algorithm.toString(), 'DartAesGcm.with192bits()');
  });

  test('information: 256 bits', () {
    algorithm = AesGcm.with256bits();
    expect(algorithm.macAlgorithm, AesGcm.aesGcmMac);
    expect(algorithm.macAlgorithm.supportsAad, isTrue);
    expect(algorithm.secretKeyLength, 32);
    expect(algorithm.nonceLength, 12);
    expect(algorithm.toString(), '$className.with256bits()');
  });

  test('information: 256 bits, nonce length = 8', () {
    algorithm = AesGcm.with256bits(nonceLength: 8);
    expect(algorithm.macAlgorithm, AesGcm.aesGcmMac);
    expect(algorithm.macAlgorithm.supportsAad, isTrue);
    expect(algorithm.secretKeyLength, 32);
    expect(algorithm.nonceLength, 8);
    expect(algorithm.toString(), '$className.with256bits(nonceLength: 8)');
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
    final secretKeyBytes = await secretKey.extractBytes();
    expect(secretKeyBytes, hasLength(32));
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
    final secretKeyBytes = await secretKey.extractBytes();
    expect(secretKeyBytes, hasLength(16));
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
    final nonce = algorithm.newNonce();
    expect(nonce, hasLength(12));
  });

  test('nonceLength: can be set to 8', () async {
    final algorithm = AesGcm.with256bits(nonceLength: 8);
    expect(algorithm.nonceLength, 8);
    final nonce = algorithm.newNonce();
    expect(nonce, hasLength(8));
  });

  test('newNonce(): two results are not equal', () async {
    final nonce = algorithm.newNonce();
    final otherNonce = algorithm.newNonce();
    expect(nonce, isNot(otherNonce));
    expect(nonce.hashCode, isNot(otherNonce.hashCode));
  });

  group('clearText is 0 bytes, secretKey is 16 bytes, nonce is 12 bytes', () {
    late AesGcm algorithm;
    late List<int> clearText;
    late SecretKey secretKey;
    late List<int> nonce;
    late List<int> cipherText;
    late Mac mac;

    setUp(() {
      algorithm = AesGcm.with128bits();
      clearText = <int>[];
      secretKey = SecretKey(List<int>.filled(16, 2));
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
    late SecretKey secretKey;
    late List<int> nonce;
    late List<int> cipherText;
    late Mac mac;

    setUp(() {
      algorithm = AesGcm.with128bits();
      clearText = <int>[1, 2, 3];
      secretKey = SecretKey(List<int>.filled(16, 2));
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
    late SecretKey secretKey;
    late List<int> nonce;
    late List<int> cipherText;
    late Mac mac;

    setUp(() {
      clearText = <int>[];
      secretKey = SecretKey(List<int>.filled(32, 2));
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
    late SecretKey secretKey;
    late List<int> nonce;
    late List<int> cipherText;
    late Mac mac;

    setUp(() {
      clearText = <int>[1, 2, 3];
      secretKey = SecretKey(List<int>.filled(32, 2));
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
      'different lengths (secretKey is 12 bytes, nonce is 16 bytes, input is 6 bytes)',
      () {
    late AesGcm cipher;
    late List<int> clearText;
    late SecretKey secretKey;
    late List<int> nonce;
    late SecretBox secretBox;
    late List<int> decrypted;

    Future<void> f(int n) async {
      clearText = List<int>.generate(n, (index) => index);
      secretKey =
          SecretKeyData(List<int>.generate(cipher.secretKeyLength, (i) => i));
      nonce = List<int>.generate(cipher.nonceLength, (i) => 100 + i);
      secretBox = await cipher.encrypt(
        clearText,
        secretKey: secretKey,
        nonce: nonce,
      );
      decrypted = await cipher.decrypt(
        secretBox,
        secretKey: secretKey,
      );
    }

    group('AES-GCM-128:', () {
      setUpAll(() {
        cipher = AesGcm.with128bits();
      });
      test('0 bytes', () async {
        await f(0);
        expect(
          hexFromBytes(secretBox.cipherText),
          '',
        );
        expect(
          hexFromBytes(secretBox.mac.bytes),
          '65 82 ac 05 e0 47 11 a8 26 bd fe 2e 14 44 40 ab',
        );
        expect(decrypted, clearText);
      });

      test('1 byte', () async {
        await f(1);
        expect(
          hexFromBytes(secretBox.cipherText),
          '1a',
        );
        expect(
          hexFromBytes(secretBox.mac.bytes),
          '93 e4 56 30 b6 f3 7a 8c 41 06 57 b2 3a e8 cd 34',
        );
        expect(decrypted, clearText);
      });

      test('15 bytes', () async {
        await f(15);
        expect(
          hexFromBytes(secretBox.cipherText),
          '1a 63 4c a6 df 07 be fd 93 37 5d 1b 8a c7 25',
        );
        expect(
          hexFromBytes(secretBox.mac.bytes),
          'f4 a4 70 db f0 cc eb cf 53 e2 a5 82 75 ec e9 ac',
        );
        expect(decrypted, clearText);
      });

      test('16 bytes', () async {
        await f(16);
        expect(
          hexFromBytes(secretBox.cipherText),
          '1a 63 4c a6 df 07 be fd 93 37 5d 1b 8a c7 25 e3',
        );
        expect(
          hexFromBytes(secretBox.mac.bytes),
          '43 7f 7d 04 95 d5 ff c6 34 67 50 0b b6 8b a4 6c',
        );
        expect(decrypted, clearText);
      });

      test('63 bytes', () async {
        await f(63);
        expect(
          hexFromBytes(secretBox.cipherText),
          '1a 63 4c a6 df 07 be fd 93 37 5d 1b 8a c7 25 e3\n'
          '20 99 6a ec 86 bc cb 4d ec 76 ab 8c a0 ef e9 ec\n'
          '9a dd 70 07 af 3d 01 b6 a2 71 0d 6d a1 af 6a 28\n'
          'eb ac 2f 40 a9 33 77 1f fb b7 3b 66 f0 a3 5b',
        );
        expect(
          hexFromBytes(secretBox.mac.bytes),
          'ca 97 12 be 42 40 99 f4 9d ed 91 7e 34 3b fd 64',
        );
        expect(decrypted, clearText);
      });

      test('64 bytes', () async {
        await f(64);
        expect(
          hexFromBytes(secretBox.cipherText),
          '1a 63 4c a6 df 07 be fd 93 37 5d 1b 8a c7 25 e3\n'
          '20 99 6a ec 86 bc cb 4d ec 76 ab 8c a0 ef e9 ec\n'
          '9a dd 70 07 af 3d 01 b6 a2 71 0d 6d a1 af 6a 28\n'
          'eb ac 2f 40 a9 33 77 1f fb b7 3b 66 f0 a3 5b 5f',
        );
        expect(
          hexFromBytes(secretBox.mac.bytes),
          '29 a6 3e 99 82 40 e3 67 e3 c9 d8 ed cc 3e a9 cd',
        );
        expect(decrypted, clearText);
      });

      test('65 bytes', () async {
        await f(65);
        expect(
          hexFromBytes(secretBox.cipherText),
          '1a 63 4c a6 df 07 be fd 93 37 5d 1b 8a c7 25 e3\n'
          '20 99 6a ec 86 bc cb 4d ec 76 ab 8c a0 ef e9 ec\n'
          '9a dd 70 07 af 3d 01 b6 a2 71 0d 6d a1 af 6a 28\n'
          'eb ac 2f 40 a9 33 77 1f fb b7 3b 66 f0 a3 5b 5f\n'
          '24',
        );
        expect(
          hexFromBytes(secretBox.mac.bytes),
          '28 d3 37 27 e6 fc 8c 70 15 dc e4 e8 8c e0 b6 f9',
        );
        expect(decrypted, clearText);
      });
    });

    group('AES-GCM-192:', () {
      setUpAll(() {
        cipher = AesGcm.with192bits();
      });
      test('0 bytes', () async {
        await f(0);
        expect(
          hexFromBytes(secretBox.cipherText),
          '',
        );
        expect(
          hexFromBytes(secretBox.mac.bytes),
          'cd 02 59 08 28 14 75 a2 15 51 9e 04 4c 5e fb db',
        );
        expect(decrypted, clearText);
      });

      test('1 byte', () async {
        await f(1);
        expect(
          hexFromBytes(secretBox.cipherText),
          'e9',
        );
        expect(
          hexFromBytes(secretBox.mac.bytes),
          'b8 d4 5c 1e b7 99 84 59 a0 63 c2 6d e4 05 06 59',
        );
        expect(decrypted, clearText);
      });

      test('15 bytes', () async {
        await f(15);
        expect(
          hexFromBytes(secretBox.cipherText),
          'e9 69 b9 7f 56 aa 08 3f db d8 e8 0a f6 ff 95',
        );
        expect(
          hexFromBytes(secretBox.mac.bytes),
          'e3 a6 62 13 25 4d 55 07 26 a0 cf 61 91 08 ae 40',
        );
        expect(decrypted, clearText);
      });

      test('16 bytes', () async {
        await f(16);
        expect(
          hexFromBytes(secretBox.cipherText),
          'e9 69 b9 7f 56 aa 08 3f db d8 e8 0a f6 ff 95 b1',
        );
        expect(
          hexFromBytes(secretBox.mac.bytes),
          '3d dc ec b2 bb e6 1d 17 26 91 88 dd 13 ac 1b 65',
        );
        expect(decrypted, clearText);
      });

      test('63 bytes', () async {
        await f(63);
        expect(
          hexFromBytes(secretBox.cipherText),
          'e9 69 b9 7f 56 aa 08 3f db d8 e8 0a f6 ff 95 b1\n'
          'cd 48 4c d9 ee 9c 67 f8 99 5a 52 d1 aa 73 86 5f\n'
          '7a 75 25 bc 7c 30 62 97 56 ba 49 9a 00 2f 0e c3\n'
          '50 5f 1c 6b b5 38 94 2a 81 a8 6c 34 af 5c ef',
        );
        expect(
          hexFromBytes(secretBox.mac.bytes),
          '47 df fe 79 65 3c a0 b4 d2 f6 44 6c 69 c2 09 80',
        );
        expect(decrypted, clearText);
      });

      test('64 bytes', () async {
        await f(64);
        expect(
          hexFromBytes(secretBox.cipherText),
          'e9 69 b9 7f 56 aa 08 3f db d8 e8 0a f6 ff 95 b1\n'
          'cd 48 4c d9 ee 9c 67 f8 99 5a 52 d1 aa 73 86 5f\n'
          '7a 75 25 bc 7c 30 62 97 56 ba 49 9a 00 2f 0e c3\n'
          '50 5f 1c 6b b5 38 94 2a 81 a8 6c 34 af 5c ef 0f',
        );
        expect(
          hexFromBytes(secretBox.mac.bytes),
          'd0 cd cf 23 50 f8 b5 59 9c 70 cf cb 61 5e 17 ce',
        );
        expect(decrypted, clearText);
      });

      test('65 bytes', () async {
        await f(65);
        expect(
          hexFromBytes(secretBox.cipherText),
          'e9 69 b9 7f 56 aa 08 3f db d8 e8 0a f6 ff 95 b1\n'
          'cd 48 4c d9 ee 9c 67 f8 99 5a 52 d1 aa 73 86 5f\n'
          '7a 75 25 bc 7c 30 62 97 56 ba 49 9a 00 2f 0e c3\n'
          '50 5f 1c 6b b5 38 94 2a 81 a8 6c 34 af 5c ef 0f\n'
          'aa',
        );
        expect(
          hexFromBytes(secretBox.mac.bytes),
          '5e 76 8a 57 bd e3 67 eb 2b 8c 24 b3 07 e8 83 83',
        );
        expect(decrypted, clearText);
      });
    });

    group('AES-GCM-256:', () {
      setUpAll(() {
        cipher = AesGcm.with256bits();
      });
      test('0 bytes', () async {
        await f(0);
        expect(
          hexFromBytes(secretBox.cipherText),
          '',
        );
        expect(
          hexFromBytes(secretBox.mac.bytes),
          '60 9b d5 0f 6a d7 6d f6 65 f0 48 ba 8c 5f d7 06',
        );
        expect(decrypted, clearText);
      });

      test('1 byte', () async {
        await f(1);
        expect(
          hexFromBytes(secretBox.cipherText),
          '48',
        );
        expect(
          hexFromBytes(secretBox.mac.bytes),
          '71 ab 1d 53 dc 3e 4e 43 9a c7 3c 21 35 06 71 09',
        );
        expect(decrypted, clearText);
      });

      test('15 bytes', () async {
        await f(15);
        expect(
          hexFromBytes(secretBox.cipherText),
          '48 1a dc 65 7d ec 50 99 36 6b 55 e3 d6 68 64',
        );
        expect(
          hexFromBytes(secretBox.mac.bytes),
          'c9 92 6b 23 c4 1d a6 b8 93 a9 49 9f 86 f5 be b5',
        );
        expect(decrypted, clearText);
      });

      test('16 bytes', () async {
        await f(16);
        expect(
          hexFromBytes(secretBox.cipherText),
          '48 1a dc 65 7d ec 50 99 36 6b 55 e3 d6 68 64 f2',
        );
        expect(
          hexFromBytes(secretBox.mac.bytes),
          '40 71 0c a1 04 91 57 d0 5b 65 d2 0e 77 bb ce c4',
        );
        expect(decrypted, clearText);
      });

      test('63 bytes', () async {
        await f(63);
        expect(
          hexFromBytes(secretBox.cipherText),
          '48 1a dc 65 7d ec 50 99 36 6b 55 e3 d6 68 64 f2\n'
          '52 d3 14 19 9f 79 e5 65 bf c8 b6 53 e7 be bb 57\n'
          'b4 c8 62 e3 68 37 bd 23 d5 da 52 14 d1 6f e4 e0\n'
          '2b 6a aa d4 14 7f 77 1f c2 c8 96 ed d3 bc 9b',
        );
        expect(
          hexFromBytes(secretBox.mac.bytes),
          '4e 90 59 1c 6d 05 55 91 17 d6 ec ae 40 78 18 c3',
        );
        expect(decrypted, clearText);
      });

      test('64 bytes', () async {
        await f(64);
        expect(
          hexFromBytes(secretBox.cipherText),
          '48 1a dc 65 7d ec 50 99 36 6b 55 e3 d6 68 64 f2\n'
          '52 d3 14 19 9f 79 e5 65 bf c8 b6 53 e7 be bb 57\n'
          'b4 c8 62 e3 68 37 bd 23 d5 da 52 14 d1 6f e4 e0\n'
          '2b 6a aa d4 14 7f 77 1f c2 c8 96 ed d3 bc 9b b5',
        );
        expect(
          hexFromBytes(secretBox.mac.bytes),
          'f5 75 23 bf 9d c3 7d 76 93 8e 33 72 1a b3 69 a8',
        );
        expect(decrypted, clearText);
      });

      test('65 bytes', () async {
        await f(65);
        expect(
          hexFromBytes(secretBox.cipherText),
          '48 1a dc 65 7d ec 50 99 36 6b 55 e3 d6 68 64 f2\n'
          '52 d3 14 19 9f 79 e5 65 bf c8 b6 53 e7 be bb 57\n'
          'b4 c8 62 e3 68 37 bd 23 d5 da 52 14 d1 6f e4 e0\n'
          '2b 6a aa d4 14 7f 77 1f c2 c8 96 ed d3 bc 9b b5\n'
          '48',
        );
        expect(
          hexFromBytes(secretBox.mac.bytes),
          'ee a7 13 36 fb f5 8c fd 5a 28 e3 9e c5 dc 7d 2d',
        );
        expect(decrypted, clearText);
      });
    });
  });
}
