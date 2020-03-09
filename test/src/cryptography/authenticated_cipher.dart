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

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';

void main() {
  test('AuthenticatedCipher', () async {
    final clearText = [1, 2, 3];

    const macAlgorithm = Hmac(sha256);
    final cipher = const AuthenticatedCipher.from(
      cipher: chacha20,
      macAlgorithm: macAlgorithm,
    );

    final secretKey = chacha20.secretKeyGenerator.generateSync();
    final nonce = chacha20.newNonce();
    final authenticatedCipherText = await cipher.encrypt(
      clearText,
      secretKey: secretKey,
      nonce: nonce,
    );
    final cipherText = authenticatedCipherText.cipherText;

    // Check MAC
    final mac = authenticatedCipherText.mac;
    expect(
      await cipher.macAlgorithm.calculateMac(
        authenticatedCipherText.cipherText,
        secretKey: secretKey,
      ),
      mac,
    );

    // Decrypt
    expect(
      await cipher.decrypt(
        AuthenticatedCipherText(
          cipherText: cipherText,
          mac: mac,
        ),
        secretKey: secretKey,
        nonce: nonce,
      ),
      clearText,
    );

    // Decrypt returns null if ciphertext is changed.
    expect(
      await cipher.decrypt(
        AuthenticatedCipherText(
          cipherText: [99],
          mac: mac,
        ),
        secretKey: secretKey,
        nonce: nonce,
      ),
      isNull,
    );

    // Decrypt returns null if MAC is changed.
    expect(
      await cipher.decrypt(
        AuthenticatedCipherText(
          cipherText: [99],
          mac: Mac(Uint8List(mac.bytes.length)),
        ),
        secretKey: secretKey,
        nonce: nonce,
      ),
      isNull,
    );
  });
}
