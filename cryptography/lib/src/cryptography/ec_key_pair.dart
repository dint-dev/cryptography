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
import 'package:cryptography/helpers.dart';

/// An opaque reference to _P-256_ / _P-384_ / _P-521_ key pair.
///
/// There are many formats for storing elliptic curve key parameters.
/// If you are encoding/decoding JWK (JSON Web Key) format, use
/// [package:jwk](https://pub.dev/packages/jwk).
///
/// ## Related classes
///   * [EcKeyPairData]
///   * [EcPublicKey]
///
/// ## Algorithms that use this class
///   * [Ecdh]
///   * [Ecdsa]
///
abstract class EcKeyPair extends KeyPair {
  factory EcKeyPair.lazy(Future<EcKeyPairData> Function() f) = _LazyEcKeyPair;

  @override
  Future<EcKeyPairData> extract();

  @override
  Future<EcPublicKey> extractPublicKey();
}

/// _P-256_ / _P-384_ / _P-521_ key pair.
///
/// There are many formats for storing elliptic curve key parameters.
/// If you are encoding/decoding JWK (JSON Web Key) format, use
/// [package:jwk](https://pub.dev/packages/jwk).
///
/// ## Related classes
///   * [EcKeyPair]
///   * [EcPublicKey]
///
/// ## Algorithms that use this class
///   * [Ecdh]
///   * [Ecdsa]
///
class EcKeyPairData extends KeyPairData implements EcKeyPair {
  /// Elliptic curve parameter `d`.
  final List<int> d;

  /// Elliptic curve parameter `x`.
  final List<int> x;

  /// Elliptic curve parameter `y`.
  final List<int> y;

  Future<EcPublicKey>? _publicKeyFuture;

  /// Constructs a private key with elliptic curve parameters.
  EcKeyPairData({
    required this.d,
    required this.x,
    required this.y,
    required KeyPairType type,
  }) : super(type: type);

  @override
  int get hashCode =>
      constantTimeBytesEquality.hash(x) ^
      type.hashCode ^
      constantTimeBytesEquality.hash(d) ^
      constantTimeBytesEquality.hash(y);

  @override
  bool operator ==(other) =>
      other is EcKeyPairData &&
      constantTimeBytesEquality.equals(x, other.x) &&
      type == other.type &&
      constantTimeBytesEquality.equals(d, other.d) &&
      constantTimeBytesEquality.equals(y, other.y);

  @override
  Future<EcKeyPairData> extract() {
    return Future<EcKeyPairData>.value(this);
  }

  @override
  Future<EcPublicKey> extractPublicKey() {
    return _publicKeyFuture ??= Future<EcPublicKey>.value(EcPublicKey(
      x: x,
      y: y,
      type: type,
    ));
  }

  @override
  String toString() => 'EcKeyPairData(..., type: $type)';
}

class _LazyEcKeyPair extends KeyPair implements EcKeyPair {
  Future<EcKeyPairData>? _localKeyPairFuture;
  Future<EcKeyPairData> Function()? _function;

  _LazyEcKeyPair(this._function);

  @override
  Future<EcKeyPairData> extract() {
    final function = _function;
    if (function != null) {
      _localKeyPairFuture = function();
      _function = null;
    }
    final localKeyPairFuture = _localKeyPairFuture;
    if (localKeyPairFuture == null) {
      throw Error();
    }
    return localKeyPairFuture;
  }

  @override
  Future<EcPublicKey> extractPublicKey() {
    return extract().then((value) => value.extractPublicKey());
  }
}
