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
  test('CipherWithAppendedMac', () async {
    final clearText = [1, 2, 3];

    final cipher = const CipherWithAppendedMac(chacha20, Hmac(sha256));

    final secretKey = await chacha20.newSecretKey();
    final nonce = chacha20.newNonce();

    // encrypt()
    final cipherText = await cipher.encrypt(
      clearText,
      secretKey: secretKey,
      nonce: nonce,
    );

    // encryptSync()
    expect(
      cipher.encryptSync(
        clearText,
        secretKey: secretKey,
        nonce: nonce,
      ),
      cipherText,
    );

    expect(
      hexFromBytes(cipherText),
      hexFromBytes([
        ...chacha20.encryptSync([1, 2, 3], secretKey: secretKey, nonce: nonce),
        ...Hmac(sha256)
            .calculateMacSync(
              cipherText.sublist(0, 3),
              secretKey: secretKey,
            )
            .bytes,
      ]),
    );

    final cipherTextData = cipher.getDataInCipherText(cipherText);
    final cipherTextMac = cipher.getMacInCipherText(cipherText);

    expect(cipherTextData, cipherText.sublist(0, cipherText.length - 32));
    expect(cipherTextMac, Mac(cipherText.sublist(cipherText.length - 32)));

    // Check MAC
    expect(
      await cipher.macAlgorithm.calculateMac(
        cipherTextData,
        secretKey: secretKey,
      ),
      cipherTextMac,
    );

    // Decrypt
    expect(
      await cipher.decrypt(
        cipherText,
        secretKey: secretKey,
        nonce: nonce,
      ),
      clearText,
    );

    // Decrypt returns null if ciphertext is changed.
    expect(
      await cipher.decrypt(
        [cipherText[0] + 1, ...cipherText.skip(1)],
        secretKey: secretKey,
        nonce: nonce,
      ),
      isNull,
    );

    // Decrypt returns null if MAC is changed.
    expect(
      await cipher.decryptSync(
        [cipherText[0] + 1, ...cipherText.skip(1)],
        secretKey: secretKey,
        nonce: nonce,
      ),
      isNull,
    );
  });
}
