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

/// A key pair composed of a private key ([KeyPairData]) and [PublicKey].
abstract class KeyPair {
  /// Returns [KeyPairData].
  ///
  /// Throws [UnsupportedError] if extraction is not possible.
  Future<KeyPairData> extract();

  /// Returns [PublicKey].
  Future<PublicKey> extractPublicKey() {
    return extract().then((value) => value.extractPublicKey());
  }
}

/// Extracted data of a [KeyPair].
///
/// ## Subclasses
///   * [EcKeyPairData]
///   * [SimpleKeyPairData]
///   * [RsaKeyPairData]
abstract class KeyPairData extends KeyPair {
  /// Type of the key pair.
  final KeyPairType type;

  KeyPairData({required this.type});

  @override
  Future<KeyPairData> extract() {
    return Future<KeyPairData>.value(this);
  }

  @override
  Future<PublicKey> extractPublicKey();
}

/// A public key of some [KeyPair].
///
/// ## Subclasses
///   * [EcPublicKey]
///   * [SimplePublicKey]
///   * [RsaPublicKey]
abstract class PublicKey {
  /// A constructor for subclasses.
  PublicKey();

  /// Type of the key pair.
  KeyPairType get type;
}
