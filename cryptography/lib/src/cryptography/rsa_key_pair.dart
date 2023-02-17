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

/// Opaque reference to RSA key pair.
///
/// The private key bytes of the key may not be in the memory. The private key
/// bytes may not even be extractable. If the private key is in memory, it's an
/// instance of [RsaKeyPairData].
///
/// The public key is always [RsaPublicKeyData].
///
/// This class is used with algorithms such as [RsaPss] and [RsaSsaPkcs1v15].
///
/// There are many formats for storing RSA key parameters.
/// If you are encoding/decoding JWK (JSON Web Key) format, use
/// [package:jwk](https://pub.dev/packages/jwk).
abstract class RsaKeyPair extends KeyPair {
  factory RsaKeyPair.lazy(Future<RsaKeyPairData> Function() f) =
      _LazyRsaSecretKey;

  @override
  Future<RsaKeyPairData> extract();

  @override
  Future<RsaPublicKey> extractPublicKey();
}

/// RSA private key.
///
/// There are many formats for storing RSA key parameters.
/// If you are encoding/decoding JWK (JSON Web Key) format, use
/// [package:jwk](https://pub.dev/packages/jwk).
///
/// ## Related classes
///   * [RsaKeyPair]
///   * [RsaPublicKey]
class RsaKeyPairData extends KeyPairData implements RsaKeyPair {
  /// RSA modulus. This is public information.
  final List<int> n;

  /// RSA exponent. This is public information.
  final List<int> e;

  /// RSA private key parameter `d`.
  final List<int> d;

  /// RSA private key parameter `p`.
  final List<int> p;

  /// RSA private key parameter `q`.
  final List<int> q;

  /// RSA private key parameter `dp`.
  final List<int>? dp;

  /// RSA private key parameter `dq`.
  final List<int>? dq;

  /// RSA private key parameter `qi`.
  final List<int>? qi;

  Future<RsaPublicKey>? _publicKeyFuture;

  RsaKeyPairData({
    required this.n,
    required this.e,
    required this.d,
    required this.p,
    required this.q,
    this.dp,
    this.dq,
    this.qi,
  }) : super(type: KeyPairType.rsa);

  @override
  int get hashCode =>
      11 * constantTimeBytesEquality.hash(n) ^
      7 * constantTimeBytesEquality.hash(e) ^
      3 * constantTimeBytesEquality.hash(d);

  @override
  bool operator ==(other) =>
      other is RsaKeyPairData &&
      constantTimeBytesEquality.equals(n, other.n) &&
      constantTimeBytesEquality.equals(e, other.e) &&
      constantTimeBytesEquality.equals(d, other.d) &&
      constantTimeBytesEquality.equals(p, other.p) &&
      constantTimeBytesEquality.equals(q, other.q) &&
      constantTimeBytesEquality.equals(dp ?? const [], other.dp ?? const []) &&
      constantTimeBytesEquality.equals(dq ?? const [], other.dq ?? const []) &&
      constantTimeBytesEquality.equals(qi ?? const [], other.qi ?? const []);

  @override
  Future<RsaKeyPairData> extract() {
    return Future<RsaKeyPairData>.value(this);
  }

  @override
  Future<RsaPublicKey> extractPublicKey() {
    return _publicKeyFuture ??=
        Future<RsaPublicKey>.value(RsaPublicKey(e: e, n: n));
  }

  @override
  String toString() => 'RsaKeyPairData(...)';
}

class _LazyRsaSecretKey extends KeyPair implements RsaKeyPair {
  Future<RsaKeyPairData>? _localSecretKeyFuture;
  Future<RsaKeyPairData> Function()? _function;

  _LazyRsaSecretKey(this._function);

  @override
  Future<RsaKeyPairData> extract() {
    final function = _function;
    if (function != null) {
      _localSecretKeyFuture = function();
      _function = null;
    }
    final localSecretKeyFuture = _localSecretKeyFuture;
    if (localSecretKeyFuture == null) {
      throw Error();
    }
    return localSecretKeyFuture;
  }

  @override
  Future<RsaPublicKey> extractPublicKey() {
    return extract().then((value) => value.extractPublicKey());
  }
}
