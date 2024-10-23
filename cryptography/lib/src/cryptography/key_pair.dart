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

/// A key pair composed of a private key ([KeyPairData]) and [PublicKey].
///
/// The main types are:
///   * [EcKeyPair] ([Ecdsa], [Ecdh])
///   * [SimpleKeyPair] ([Ed25519], [X25519])
///   * [RsaKeyPair] (RSA-based algorithms)
abstract class KeyPair {
  bool _hasBeenDestroyed = false;

  /// Whether [destroy] has been called.
  bool get hasBeenDestroyed => _hasBeenDestroyed;

  /// Overwrites sensitive parts of the private key data with zeroes and
  /// prevents the private key from being used anymore.
  ///
  /// The method [extractPublicKey] should still work after calling this method.
  @mustCallSuper
  void destroy() {
    _hasBeenDestroyed = true;
  }

  /// Reads the private key into memory.
  ///
  /// Throws [UnsupportedError] if extraction is not possible.
  Future<KeyPairData> extract();

  /// Reads the public key.
  Future<PublicKey> extractPublicKey();
}

/// Extracted data of a [KeyPair].
///
/// The main types are:
///   * [EcKeyPairData] ([Ecdsa], [Ecdh])
///   * [SimpleKeyPairData] ([Ed25519], [X25519])
///   * [RsaKeyPairData] (RSA-based algorithms)
abstract class KeyPairData extends KeyPair {
  /// Type of the key pair.
  final KeyPairType type;

  KeyPairData({required this.type});

  /// Public key.
  PublicKey get publicKey;

  /// Copies the private key.
  KeyPairData copy();

  @override
  Future<KeyPairData> extract() async {
    return this;
  }

  @override
  String toString() => '$runtimeType(..., type: $type)';
}

/// A public key of some [KeyPair].
///
/// The main types are:
///   * [EcPublicKey] ([Ecdsa], [Ecdh])
///   * [SimplePublicKey] ([Ed25519], [X25519])
///   * [RsaPublicKey] (RSA-based algorithms)
abstract class PublicKey {
  /// A constructor for subclasses.
  PublicKey();

  /// Type of the key pair.
  KeyPairType get type;

  @override
  String toString() => '$runtimeType(..., type: $type)';
}
