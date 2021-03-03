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
import 'package:cryptography_flutter/cryptography_flutter.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  Cryptography.freezeInstance(FlutterCryptography());

  final clearText = List<int>.filled(10000, 1);

  group('AesCbc():', () {
    late AesCbc algorithm;
    late SecretKey secretKey;
    late List<int> nonce;
    late SecretBox secretBox;

    setUp(() async {
      algorithm = AesCbc.with256bits(macAlgorithm: Hmac.sha256());
      secretKey = await algorithm.newSecretKey();
      nonce = algorithm.newNonce();

      // Construct expected secret box with pure Dart implementation.
      secretBox = await algorithm.encrypt(
        clearText,
        secretKey: secretKey,
        nonce: nonce,
      );
    });

    test('encrypt', () async {
      final actual = await algorithm.encrypt(
        clearText,
        secretKey: secretKey,
        nonce: nonce,
      );
      expect(actual.cipherText, orderedEquals(secretBox.cipherText));
      expect(actual.mac, secretBox.mac);
    });

    test('decrypt', () async {
      final actual = await algorithm.decrypt(
        secretBox,
        secretKey: secretKey,
      );
      expect(actual, orderedEquals(clearText));
    });
  });

  group('AesCtr():', () {
    late AesCtr algorithm;
    late SecretKey secretKey;
    late List<int> nonce;
    late SecretBox secretBox;

    setUp(() async {
      algorithm = AesCtr.with256bits(macAlgorithm: Hmac.sha256());
      secretKey = await algorithm.newSecretKey();
      nonce = algorithm.newNonce();

      // Construct expected secret box with pure Dart implementation.
      secretBox = await algorithm.encrypt(
        clearText,
        secretKey: secretKey,
        nonce: nonce,
      );
    });

    test('encrypt', () async {
      final actual = await algorithm.encrypt(
        clearText,
        secretKey: secretKey,
        nonce: nonce,
      );
      expect(actual.cipherText, orderedEquals(secretBox.cipherText));
      expect(actual.mac, secretBox.mac);
    });

    test('decrypt', () async {
      final actual = await algorithm.decrypt(
        secretBox,
        secretKey: secretKey,
      );
      expect(actual, orderedEquals(clearText));
    });
  });

  group('AesGcm():', () {
    late AesGcm algorithm;
    late SecretKey secretKey;
    late List<int> nonce;
    late SecretBox secretBox;

    setUp(() async {
      algorithm = AesGcm.with256bits();
      secretKey = await algorithm.newSecretKey();
      nonce = algorithm.newNonce();

      // Construct expected secret box with pure Dart implementation.
      secretBox = await algorithm.encrypt(
        clearText,
        secretKey: secretKey,
        nonce: nonce,
      );
    });

    test('encrypt', () async {
      expect(algorithm, isA<FlutterAesGcm>());
      final actual = await algorithm.encrypt(
        clearText,
        secretKey: secretKey,
        nonce: nonce,
      );
      expect(actual.cipherText, orderedEquals(secretBox.cipherText));
      expect(actual.mac, secretBox.mac);
    });

    test('decrypt', () async {
      expect(algorithm, isA<FlutterAesGcm>());
      final actual = await algorithm.decrypt(
        secretBox,
        secretKey: secretKey,
      );
      expect(actual, orderedEquals(clearText));
    });
  });

  group('Chacha20.poly1305Aead():', () {
    final algorithm = Chacha20.poly1305Aead();
    late SecretKey secretKey;
    late List<int> nonce;
    late SecretBox secretBox;

    setUp(() async {
      secretKey = await algorithm.newSecretKey();
      nonce = algorithm.newNonce();

      // Construct expected secret box with pure Dart implementation.
      secretBox = await algorithm.encrypt(
        clearText,
        secretKey: secretKey,
        nonce: nonce,
      );
    });

    test('encrypt', () async {
      expect(algorithm, isA<FlutterChacha20>());
      final actual = await algorithm.encrypt(
        clearText,
        secretKey: secretKey,
        nonce: nonce,
      );
      expect(actual.cipherText, orderedEquals(secretBox.cipherText));
      expect(actual.mac, secretBox.mac);
    });

    test('decrypt', () async {
      expect(algorithm, isA<FlutterChacha20>());
      final actual = await algorithm.decrypt(
        secretBox,
        secretKey: secretKey,
      );
      expect(actual, orderedEquals(clearText));
    });
  });
}
