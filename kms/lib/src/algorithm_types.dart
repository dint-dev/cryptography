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

/// Describes type of a secret key managed by some [Kms].
enum CipherType {
  any,

  /// AES-CBC.
  aesCbc,

  /// AES-CTR with a 96-bit nonce and a 32-bit counter.
  aesCtr32,

  /// AES-GCM.
  aesGcm,

  /// Chacha20.
  chacha20,
}

/// Describes key exchange type of a secret key managed by some [Kms].
enum KeyExchangeType {
  /// P256 (secp256r1).
  p256,

  /// P384 (secp384r1).
  p384,

  /// P521 (secp521r1).
  p521,

  /// X25519.
  x25519,
}

/// Signature algorithms.
enum SignatureType {
  /// P256 (secp256r1) with SHA256 hash.
  p256Sha256,

  /// P384 (secp384r1) with SHA384 hash.
  p384Sha384,

  /// Ed25519.
  ed25519,
}
