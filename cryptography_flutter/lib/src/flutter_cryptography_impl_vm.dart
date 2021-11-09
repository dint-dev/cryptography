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

import 'package:cryptography/browser.dart';
import 'package:cryptography/cryptography.dart';

import '../cryptography_flutter.dart';

class FlutterCryptographyImpl extends BrowserCryptography
    implements FlutterCryptography {
  FlutterCryptographyImpl();

  @override
  AesCbc aesCbc({
    required MacAlgorithm macAlgorithm,
    int secretKeyLength = 32,
  }) {
    return FlutterAesCbc(super.aesCbc(
      macAlgorithm: macAlgorithm,
      secretKeyLength: secretKeyLength,
    ));
  }

  @override
  AesCtr aesCtr({
    required MacAlgorithm macAlgorithm,
    int secretKeyLength = 32,
    int counterBits = 64,
  }) {
    return FlutterAesCtr(super.aesCtr(
      macAlgorithm: macAlgorithm,
      secretKeyLength: secretKeyLength,
      counterBits: counterBits,
    ));
  }

  @override
  AesGcm aesGcm({int secretKeyLength = 32, int nonceLength = 12}) {
    return FlutterAesGcm(super.aesGcm(
      secretKeyLength: secretKeyLength,
      nonceLength: nonceLength,
    ));
  }

  @override
  Chacha20 chacha20({required MacAlgorithm macAlgorithm}) {
    return FlutterChacha20(super.chacha20(macAlgorithm: macAlgorithm));
  }

  @override
  Chacha20 chacha20Poly1305Aead() {
    return FlutterChacha20(super.chacha20Poly1305Aead());
  }

// @override
// Ecdh ecdhP256({required int length}) {
//   return FlutterEcdh.p256(super.ecdhP256(length: length));
// }
//
// @override
// Ecdh ecdhP384({required int length}) {
//   return FlutterEcdh.p384(super.ecdhP384(length: length));
// }
//
// @override
// Ecdh ecdhP521({required int length}) {
//   return FlutterEcdh.p521(super.ecdhP521(length: length));
// }
//
// @override
// Ecdsa ecdsaP256(HashAlgorithm hashAlgorithm) {
//   return FlutterEcdsa.p256(super.ecdsaP256(hashAlgorithm));
// }
//
// @override
// Ecdsa ecdsaP384(HashAlgorithm hashAlgorithm) {
//   return FlutterEcdsa.p384(super.ecdsaP384(hashAlgorithm));
// }
//
// @override
// Ecdsa ecdsaP521(HashAlgorithm hashAlgorithm) {
//   return FlutterEcdsa.p521(super.ecdsaP521(hashAlgorithm));
// }
}
