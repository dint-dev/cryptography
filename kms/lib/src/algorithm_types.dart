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

const Map<CipherType, Cipher> defaultCipherImplementations = {
  CipherType.aesCbcHmacSha256: CipherWithAppendedMac(aesCbc, Hmac(sha256)),
  CipherType.aesCtrHmacSha256: CipherWithAppendedMac(aesCtr, Hmac(sha256)),
  CipherType.aesGcm: aesGcm,
  CipherType.chacha20Poly1305Aead: chacha20Poly1305Aead,
};

const Map<KeyExchangeType, KeyExchangeAlgorithm>
    defaultKeyExchangeImplementations = {
  KeyExchangeType.ecdhP256: ecdhP256,
  KeyExchangeType.x25519: x25519,
};

const Map<SignatureType, SignatureAlgorithm> defaultSignatureImplementations = {
  SignatureType.ed25519: ed25519,
  SignatureType.ecdsaP256sha256: ecdsaP256Sha256,
};

/// Describes type of a secret key managed by some [Kms].
enum CipherType {
  /// AES-CBC + HMAC-SHA256.
  aesCbcHmacSha256,

  /// AES-CTR + HMAC-SHA256.
  aesCtrHmacSha256,

  /// AES-GCM.
  aesGcm,

  /// Chacha20 + Poly1305.
  chacha20Poly1305Aead,
}

/// Describes key exchange type of a secret key managed by some [Kms].
enum KeyExchangeType {
  /// ECDH NIST P-256 (secp256r1).
  ecdhP256,

  /// X25519.
  x25519,
}

/// Signature algorithms.
enum SignatureType {
  /// ECDSA NIST P-256 (secp256r1) with SHA256 hash.
  ecdsaP256sha256,

  /// Ed25519.
  ed25519,
}
