// Copyright 2019-2020 Gohilla.
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
import 'package:meta/meta.dart';

/// Static information about a key pair type.
class KeyPairType<S extends KeyPairData, P extends PublicKey> {
  /// Key pair type for [Ed25519].
  static const KeyPairType ed25519 =
      KeyPairType<SimpleKeyPairData, SimplePublicKey>._(
    name: 'ed25519',
    ellipticBits: 256,
    privateKeyLength: 32,
    publicKeyLength: 32,
  );

  /// Key pair type for [Ecdh] and [Ecdsa] with P-256 curve.
  ///
  /// Keys of this type can be generated with [EcKeyPairGenerator].
  static const KeyPairType p256 = KeyPairType<EcKeyPairData, EcPublicKey>._(
    name: 'p256',
    ellipticBits: 256,
    webCryptoCurve: 'P-256',
  );

  /// Key pair type for [Ecdh] and [Ecdsa] with P-256 curve.
  ///
  /// Keys of this type can be generated with [EcKeyPairGenerator].
  static const KeyPairType p256k = KeyPairType<EcKeyPairData, EcPublicKey>._(
    name: 'p256k',
    ellipticBits: 256,
    webCryptoCurve: 'P-256K',
  );

  /// Key pair type for [Ecdh] and [Ecdsa] with P-384 curve.
  ///
  /// Keys of this type can be generated with [EcKeyPairGenerator].
  static const KeyPairType p384 = KeyPairType<EcKeyPairData, EcPublicKey>._(
    name: 'p384',
    ellipticBits: 384,
    webCryptoCurve: 'P-384',
  );

  /// Key pair type for [Ecdh] and [Ecdsa] with P-521 curve.
  ///
  /// Keys of this type can be generated with [EcKeyPairGenerator].
  static const KeyPairType p521 = KeyPairType<EcKeyPairData, EcPublicKey>._(
    name: 'p521',
    ellipticBits: 521,
    webCryptoCurve: 'P-521',
  );

  /// Key pair type for [RsaPss] and [RsaSsaPkcs1v15].
  ///
  /// Keys of this type can be generated with [RsaKeyPairGenerator].
  static const KeyPairType rsa = KeyPairType<RsaKeyPairData, RsaPublicKey>._(
    name: 'rsa',
    ellipticBits: 0,
  );

  /// Key pair type for [X25519].
  static const KeyPairType x25519 =
      KeyPairType<SimpleKeyPairData, SimplePublicKey>._(
    name: 'x25519',
    ellipticBits: 256,
    privateKeyLength: 32,
    publicKeyLength: 32,
  );

  /// Name of the algorithm (for debugging purposes).
  final String name;

  /// Number of bits if this is an elliptic algorithm (for debugging purposes).
  final int ellipticBits;

  /// Maximum private key length (in bytes).
  ///
  /// The value is -1 if multiple lengths is valid.
  final int privateKeyLength;

  /// Maximum public key length (in bytes).
  ///
  /// The value is -1 if multiple lengths is valid.
  final int publicKeyLength;

  /// Web Crypto curve name.
  final String? webCryptoCurve;

  @literal
  const KeyPairType._({
    required this.name,
    this.ellipticBits = -1,
    this.privateKeyLength = -1,
    this.publicKeyLength = -1,
    this.webCryptoCurve,
  });

  bool isValidKeyPairData(KeyPairData keyPair) =>
      keyPair is S && keyPair.type == this;

  bool isValidPublicKey(PublicKey publicKey) =>
      publicKey is P && publicKey.type == this;

  @override
  String toString() => 'KeyPairType.$name';
}
