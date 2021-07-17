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

import 'package:collection/collection.dart';
import 'package:cryptography/cryptography.dart';

/// Public key of _P-256_ / _P-384_ / _P-521_ key pair.
///
/// There are many formats for storing elliptic curve key parameters.
/// If you are encoding/decoding JWK (JSON Web Key) format, use
/// [package:jwk](https://pub.dev/packages/jwk).
///
/// ## Related classes
///   * [EcKeyPair]
///   * [EcKeyPairData]
///
/// ## Algorithms that use this class
///   * [Ecdh]
///   * [Ecdsa]
///
class EcPublicKey extends PublicKey {
  /// Elliptic curve parameter `x`.
  final List<int> x;

  /// Elliptic curve parameter `y`.
  final List<int> y;

  @override
  final KeyPairType type;

  EcPublicKey({required this.x, required this.y, required this.type});

  @override
  int get hashCode =>
      const ListEquality<int>().hash(x) ^
      const ListEquality<int>().hash(y) ^
      type.hashCode;

  @override
  bool operator ==(other) =>
      other is EcPublicKey &&
      const ListEquality<int>().equals(x, other.x) &&
      const ListEquality<int>().equals(y, other.y) &&
      type == other.type;

  @override
  String toString() =>
      'EcPublicKey(x: [${x.join(',')}], y: [${y.join(',')}], type: $type)';
}
