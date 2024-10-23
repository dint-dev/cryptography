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
import 'package:cryptography_plus/helpers.dart';

/// RSA public key.
///
/// There are many formats for storing RSA key parameters.
/// If you are encoding/decoding JWK (JSON Web Key) format, use
/// [package:jwk](https://pub.dev/packages/jwk).
///
/// ## Related classes
///   * [RsaKeyPair]
///   * [RsaPublicKey]
///
/// ## Algorithms that use this class
///   * [RsaPss]
///   * [RsaSsaPkcs1v15]
class RsaPublicKey extends PublicKey {
  final List<int> e;
  final List<int> n;

  RsaPublicKey({
    required this.e,
    required this.n,
  });

  @override
  int get hashCode =>
      constantTimeBytesEquality.hash(e) ^ constantTimeBytesEquality.hash(n);

  @override
  KeyPairType get type => KeyPairType.rsa;

  @override
  bool operator ==(other) =>
      other is RsaPublicKey &&
      constantTimeBytesEquality.equals(e, other.e) &&
      constantTimeBytesEquality.equals(n, other.n);

  @override
  String toString() {
    final e = this.e;
    final es = '[${e.join(', ')}]';
    final n = this.n;
    final ns = n.length <= 2
        ? '[${n.join(',')}]'
        : '[..., ${n.skip(n.length - 2).join(', ')}]';
    return 'RsaPublicKey(\n  e: $es,\n  n: $ns,\n)';
  }
}
