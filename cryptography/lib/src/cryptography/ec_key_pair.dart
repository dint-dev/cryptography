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

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/helpers.dart';

/// An opaque reference to _P-256_ / _P-384_ / _P-521_ key pair.
///
/// The private key bytes of the key may not be in the memory. The private key
/// bytes may not even be extractable. If the private key is in memory, it's an
/// instance of [EcKeyPairData].
///
/// The public key is always [EcPublicKey].
///
/// This class is used with algorithms such as [Ecdh.p256] and [Ecdsa.p256].
///
/// There are many formats for storing elliptic curve key parameters.
/// If you are encoding/decoding JWK (JSON Web Key) format, use
/// [package:jwk](https://pub.dev/packages/jwk).
abstract class EcKeyPair extends KeyPair {
  /// Constructor for subclasses.
  EcKeyPair.constructor();

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
  final SensitiveBytes _d;

  /// Elliptic curve parameter `x`.
  final List<int> x;

  /// Elliptic curve parameter `y`.
  final List<int> y;

  @override
  final EcPublicKey publicKey;

  /// Debugging label.
  final String? debugLabel;

  /// Constructs a private key with elliptic curve parameters.
  EcKeyPairData({
    required List<int> d,
    required this.x,
    required this.y,
    required KeyPairType type,
    this.debugLabel,
  })  : _d = SensitiveBytes(d),
        publicKey = EcPublicKey(
          x: x,
          y: y,
          type: type,
        ),
        super(type: type);

  /// Elliptic curve parameter `d`.
  List<int> get d {
    final d = _d;
    if (d.hasBeenDestroyed) {
      throw UnsupportedError('Private key has been destroyed: $this');
    }
    return d;
  }

  @override
  int get hashCode =>
      type.hashCode ^
      constantTimeBytesEquality.hash(x) ^
      constantTimeBytesEquality.hash(y);

  @override
  bool operator ==(other) =>
      other is EcKeyPairData &&
      constantTimeBytesEquality.equals(x, other.x) &&
      constantTimeBytesEquality.equals(y, other.y) &&
      type == other.type &&
      (hasBeenDestroyed ||
          other.hasBeenDestroyed ||
          constantTimeBytesEquality.equals(d, other.d));

  @override
  EcKeyPairData copy() {
    if (hasBeenDestroyed) {
      throw StateError('Private key has been destroyed');
    }
    return EcKeyPairData(
      d: d,
      x: x,
      y: y,
      type: type,
      debugLabel: debugLabel,
    );
  }

  @override
  void destroy() {
    super.destroy();
    _d.destroy();
  }

  @override
  Future<EcKeyPairData> extract() async {
    if (hasBeenDestroyed) {
      throw StateError('Private key has been destroyed');
    }
    return this;
  }

  @override
  Future<EcPublicKey> extractPublicKey() async {
    if (hasBeenDestroyed) {
      throw StateError('Private key has been destroyed');
    }
    return publicKey;
  }

  @override
  String toString() {
    final debugLabel = this.debugLabel;
    if (debugLabel != null) {
      return 'EcKeyPairData(..., type: $type, debugLabel: $debugLabel)';
    }
    return 'EcKeyPairData(..., type: $type)';
  }
}
