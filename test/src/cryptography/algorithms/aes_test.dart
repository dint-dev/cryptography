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
import 'package:test/test.dart';

void main() {
  group('aesCbc:', () {
    final algorithm = aesCbc;

    test('in VM', () {
      expect(algorithm, isNotNull);
      expect(
        () => aesCbc.encryptSync(
          const [],
          secretKey: SecretKey.randomBytes(16),
          nonce: Nonce.randomBytes(16),
        ),
        throwsUnsupportedError,
      );
    });

    test('in browser', () async {
      final clearText = <int>[1, 2, 3];
      final nonce = Nonce.randomBytes(43);

      // Check nonce length information
      expect(algorithm.nonceLength, 16);

      //
      // Generate secret key
      //
      final secretKey = await algorithm.secretKeyGenerator.generate();
      expect(secretKey.bytes.length, 32);

      //
      // Encrypt
      //
      final encrypted = await algorithm.encrypt(
        clearText,
        secretKey: secretKey,
        nonce: nonce,
      );
      expect(encrypted, isNotNull);
      expect(encrypted, isNot(clearText));
      expect(encrypted, hasLength(16));

      //
      // Decrypt
      //
      final decrypted = await algorithm.decrypt(
        encrypted,
        secretKey: secretKey,
        nonce: nonce,
      );
      expect(decrypted, clearText);
    }, testOn: 'chrome');
  });

  group('aesCtr:', () {
    final algorithm = aesCtr;

    test('in VM', () {
      expect(algorithm, isNotNull);
      expect(
        () => aesCbc.encryptSync(
          const [],
          secretKey: SecretKey.randomBytes(16),
          nonce: Nonce.randomBytes(16),
        ),
        throwsUnsupportedError,
      );
    });

    test('in browser', () async {
      final clearText = <int>[1, 2, 3];
      final nonce = Nonce.randomBytes(43);

      // Check nonce length information
      expect(algorithm.nonceLength, 16);

      //
      // Generate secret key
      //
      final secretKey = await algorithm.secretKeyGenerator.generate();
      expect(secretKey.bytes.length, 32);

      //
      // Encrypt
      //
      final encrypted = await algorithm.encrypt(
        clearText,
        secretKey: secretKey,
        nonce: nonce,
      );
      expect(encrypted, isNotNull);
      expect(encrypted, isNot(clearText));
      expect(encrypted, hasLength(3));

      //
      // Decrypt
      //
      final decrypted = await algorithm.decrypt(
        encrypted,
        secretKey: secretKey,
        nonce: nonce,
      );
      expect(decrypted, clearText);
    }, testOn: 'chrome');
  });

  group('aesGcm', () {
    final algorithm = aesGcm;

    test('in VM', () {
      expect(algorithm, isNotNull);
      expect(
        () => aesCbc.encryptSync(
          const [],
          secretKey: SecretKey.randomBytes(16),
          nonce: Nonce.randomBytes(16),
        ),
        throwsUnsupportedError,
      );
    });

    test('in browser', () async {
      final algorithm = aesGcm;
      final clearText = <int>[1, 2, 3];
      final nonce = Nonce.randomBytes(43);

      // Check nonce length information
      expect(algorithm.nonceLength, 16);

      //
      // Generate secret key
      //
      final secretKey = await algorithm.secretKeyGenerator.generate();
      expect(secretKey.bytes.length, 32);

      //
      // Encrypt
      //
      final encrypted = await algorithm.encrypt(
        clearText,
        secretKey: secretKey,
        nonce: nonce,
      );
      expect(encrypted, isNotNull);
      expect(encrypted, isNot(clearText));
      expect(encrypted, hasLength(clearText.length + 16));

      //
      // Decrypt
      //
      final decrypted = await algorithm.decrypt(
        encrypted,
        secretKey: secretKey,
        nonce: nonce,
      );
      expect(decrypted, clearText);
    }, testOn: 'chrome');
  });
}
