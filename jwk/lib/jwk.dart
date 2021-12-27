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

/// JWK (JSON Web Key) encoding and decoding.
library jwk;

import 'dart:convert';

import 'package:collection/collection.dart';
import 'package:cryptography/cryptography.dart';

/// A JWK ([RFC 7517](https://tools.ietf.org/html/rfc7517): "JSON Web Key")
/// formatted cryptographic key.
///
/// ## Examples of JSON representation
/// ### AES key
/// ```json
/// final key = Jwt.fromJson({
///   "kty": "OKP",
///   "d": "{BYTES_IN_BASE64URI}",
/// });
/// ```
///
/// ### Ed25519 key
/// ```json
/// final key = Jwt.fromJson({
///   "kty": "OKP",
///   "crv": "Ed25519",
///   "d": "{BYTES_IN_BASE64URI}",
///   "x": "{BYTES_IN_BASE64URI}",
/// });
/// ```
///
/// ### P-256 key
/// ```json
/// final key = Jwt.fromJson({
///   "kty": "EC",
///   "crv": "P-256",
///   "d": "{BYTES_IN_BASE64URI}",
///   "x": "{BYTES_IN_BASE64URI}",
///   "y": "{BYTES_IN_BASE64URI}",
/// });
/// ```
///
/// ## RSA key
/// ```json
/// final key = Jwt.fromJson({
///   "kty": "RSA",
///   "n": "{BYTES_IN_BASE64URI}",
///   "e": "{BYTES_IN_BASE64URI}",
///   "d": "{BYTES_IN_BASE64URI}",
///   "q": "{BYTES_IN_BASE64URI}",
///   "dp": "{BYTES_IN_BASE64URI}",
///   "dq": "{BYTES_IN_BASE64URI}",
///   "qi": "{BYTES_IN_BASE64URI}",
/// })
/// ```
class Jwk {
  /// Key type.
  ///
  /// Possible values:
  ///   * "EC" (Elliptic Key)
  ///   * "OKP" (Octet Key Pair)
  ///   * "RSA" (RSA key)
  final String? kty;

  /// Algorithm of the key.
  final String? alg;

  final String? cty;

  /// Elliptic curve name.
  ///
  /// Possible values:
  ///   * "Ed25519"
  ///   * "P-256"
  ///   * "P-384"
  ///   * "P-521"
  ///   * "X25519"
  final String? crv;

  /// RSA private key parameter `d`.
  final List<int>? d;

  /// RSA private key parameter `dp`.
  final List<int>? dp;

  /// RSA private key parameter `dq`.
  final List<int>? dq;

  /// RSA exponent. This is public information.
  final List<int>? e;

  /// ID of the key.
  final String? kid;

  /// Operations.
  final String? keyOps;

  /// RSA modulus. This is public information.
  final List<int>? n;

  /// RSA private key parameter `p`.
  final List<int>? p;

  /// RSA private key parameter `q`.
  final List<int>? q;

  /// RSA private key parameter `qi`.
  final List<int>? qi;

  /// Use of the key.
  final String? use;

  /// Parameter `x`.
  final List<int>? x;

  /// X.509 Certificate Chain.
  final List<int>? x5c;

  /// X.509 Certificate SHA-1 Thumbprint.
  final List<int>? x5t;

  /// X.509 URL.
  final String? x5u;

  /// Parameter `y`.
  final List<int>? y;

  const Jwk({
    this.alg,
    this.crv,
    this.cty,
    this.d,
    this.dp,
    this.dq,
    this.e,
    this.keyOps,
    this.kid,
    this.kty,
    this.n,
    this.p,
    this.q,
    this.qi,
    this.use,
    this.x,
    this.x5c,
    this.x5t,
    this.x5u,
    this.y,
  });

  @override
  int get hashCode =>
      alg.hashCode ^
      crv.hashCode ^
      kid.hashCode ^
      kty.hashCode ^
      use.hashCode ^
      x.hashCode ^
      y.hashCode;

  @override
  bool operator ==(other) =>
      other is Jwk &&
      alg == other.alg &&
      crv == other.crv &&
      cty == other.cty &&
      d == other.d &&
      dp == other.dp &&
      dq == other.dq &&
      e == other.e &&
      keyOps == other.keyOps &&
      kid == other.kid &&
      kty == other.kty &&
      n == other.n &&
      p == other.p &&
      q == other.q &&
      qi == other.qi &&
      use == other.use &&
      x == other.x &&
      x5c == other.x5c &&
      x5t == other.x5t &&
      x5u == other.x5u &&
      y == other.y;

  JwkBuilder toBuilder() {
    return JwkBuilder()
      ..alg = alg
      ..crv = crv
      ..cty = cty
      ..d = d
      ..dp = dp
      ..dq = dq
      ..e = e
      ..kid = kid
      ..kty = kty
      ..n = n
      ..p = p
      ..q = q
      ..qi = qi
      ..use = use
      ..x = x
      ..x5c = x5c
      ..x5t = x5t
      ..x5u = x5u
      ..y = y;
  }

  Map<String, Object?> toJson() {
    final result = <String, Object?>{};
    {
      final value = alg;
      if (value != null) {
        result['alg'] = value;
      }
    }
    {
      final value = crv;
      if (value != null) {
        result['crv'] = value;
      }
    }
    {
      final value = cty;
      if (value != null) {
        result['cty'] = value;
      }
    }
    {
      final value = d;
      if (value != null) {
        result['d'] = _base64UriEncode(value);
      }
    }
    {
      final value = dp;
      if (value != null) {
        result['dp'] = _base64UriEncode(value);
      }
    }
    {
      final value = dq;
      if (value != null) {
        result['dq'] = _base64UriEncode(value);
      }
    }
    {
      final value = e;
      if (value != null) {
        result['e'] = _base64UriEncode(value);
      }
    }
    {
      final value = kty;
      if (value != null) {
        result['kty'] = value;
      }
    }
    {
      final value = keyOps;
      if (value != null) {
        result['key_ops'] = value;
      }
    }
    {
      final value = kid;
      if (value != null) {
        result['kid'] = value;
      }
    }
    {
      final value = n;
      if (value != null) {
        result['n'] = _base64UriEncode(value);
      }
    }
    {
      final value = p;
      if (value != null) {
        result['p'] = _base64UriEncode(value);
      }
    }
    {
      final value = q;
      if (value != null) {
        result['q'] = _base64UriEncode(value);
      }
    }
    {
      final value = qi;
      if (value != null) {
        result['qi'] = _base64UriEncode(value);
      }
    }
    {
      final value = use;
      if (value != null) {
        result['use'] = value;
      }
    }
    {
      final value = x;
      if (value != null) {
        result['x'] = _base64UriEncode(value);
      }
    }
    {
      final value = x5c;
      if (value != null) {
        result['x5c'] = _base64UriEncode(value);
      }
    }
    {
      final value = x5t;
      if (value != null) {
        result['x5t'] = _base64UriEncode(value);
      }
    }
    {
      final value = x5u;
      if (value != null) {
        result['x5u'] = value;
      }
    }
    {
      final value = y;
      if (value != null) {
        result['y'] = _base64UriEncode(value);
      }
    }
    return Map<String, Object?>.unmodifiable(result);
  }

  KeyPair toKeyPair() {
    switch (kty) {
      case 'EC':
        final type = const <String, KeyPairType>{
          'P-256': KeyPairType.p256,
          'P-384': KeyPairType.p384,
          'P-521': KeyPairType.p521,
        }[crv];
        if (type == null) {
          throw StateError('Unsupported "crv": "$crv"');
        }
        return EcKeyPairData(
          d: List<int>.unmodifiable(d ?? const <int>[]),
          x: List<int>.unmodifiable(x ?? const <int>[]),
          y: List<int>.unmodifiable(y ?? const <int>[]),
          type: type,
        );

      case 'OKP':
        if (crv == 'Ed25519') {
          final y = this.y!;
          return SimpleKeyPair.lazy(
            () async {
              return Ed25519().newKeyPairFromSeed(y);
            },
          );
        }
        if (crv == 'X25519') {
          final y = this.y!;
          return SimpleKeyPair.lazy(
            () async {
              return X25519().newKeyPairFromSeed(y);
            },
          );
        }
        throw StateError('Unsupported "crv": "$crv"');

      case 'RSA':
        return RsaKeyPairData(
          e: List<int>.unmodifiable(e ?? const <int>[]),
          d: List<int>.unmodifiable(d ?? const <int>[]),
          dp: List<int>.unmodifiable(dp ?? const <int>[]),
          dq: List<int>.unmodifiable(dq ?? const <int>[]),
          n: List<int>.unmodifiable(n ?? const <int>[]),
          p: List<int>.unmodifiable(p ?? const <int>[]),
          q: List<int>.unmodifiable(q ?? const <int>[]),
          qi: List<int>.unmodifiable(qi ?? const <int>[]),
        );

      default:
        throw StateError('Not a key pair (kty: $kty)');
    }
  }

  PublicKey? toPublicKey() {
    switch (kty) {
      case 'EC':
        final type = const <String, KeyPairType>{
          'P-256': KeyPairType.p256,
          'P-384': KeyPairType.p384,
          'P-521': KeyPairType.p521,
        }[crv];
        if (type == null) {
          throw StateError('Unsupported "crv": "$crv"');
        }
        return EcPublicKey(
          x: List<int>.unmodifiable(x ?? const <int>[]),
          y: List<int>.unmodifiable(y ?? const <int>[]),
          type: type,
        );

      case 'OKP':
        final type = const <String, KeyPairType>{
          'Ed25519': KeyPairType.ed25519,
          'X25519': KeyPairType.x25519,
        }[crv];
        if (type == null) {
          throw StateError('Unsupported "crv": "$crv"');
        }
        return SimplePublicKey(
          List<int>.unmodifiable(x ?? const <int>[]),
          type: type,
        );

      case 'RSA':
        return RsaPublicKey(
          e: List<int>.unmodifiable(e ?? const <int>[]),
          n: List<int>.unmodifiable(n ?? const <int>[]),
        );
    }
    return null;
  }

  SecretKey toSecretKey() {
    switch (kty) {
      case 'OCK':
        return SecretKey(List<int>.unmodifiable(x ?? const <int>[]));

      default:
        throw StateError('Not a secret key (kty: $kty)');
    }
  }

  List<int> toUtf8() {
    return utf8.encode(json.encode(toJson()));
  }

  /// Constructs a private key from decoded JSON tree.
  static Jwk fromJson(Map jwk) {
    final builder = JwkBuilder();
    for (var entry in jwk.entries) {
      final key = entry.key;
      final value = entry.value;
      switch (key) {
        case 'alg':
          builder.alg = value as String;
          break;
        case 'crv':
          builder.crv = value as String;
          break;
        case 'd':
          builder.d = _base64UriDecode(value as String);
          break;
        case 'dp':
          builder.dp = _base64UriDecode(value as String);
          break;
        case 'dq':
          builder.dq = _base64UriDecode(value as String);
          break;
        case 'e':
          builder.e = _base64UriDecode(value as String);
          break;
        case 'key_ops':
          builder.keyOps = value as String;
          break;
        case 'kid':
          builder.kid = value as String;
          break;
        case 'kty':
          builder.kty = value as String;
          break;
        case 'n':
          builder.n = _base64UriDecode(value as String);
          break;
        case 'p':
          builder.p = _base64UriDecode(value as String);
          break;
        case 'q':
          builder.q = _base64UriDecode(value as String);
          break;
        case 'qi':
          builder.qi = _base64UriDecode(value as String);
          break;
        case 'use':
          builder.use = value as String;
          break;
        case 'x':
          builder.x = _base64UriDecode(value as String);
          break;
        case 'x5c':
          builder.x5c = _base64UriDecode(value as String);
          break;
        case 'x5t':
          builder.x5t = _base64UriDecode(value as String);
          break;
        case 'x5u':
          builder.x5u = value as String;
          break;
        case 'y':
          builder.y = _base64UriDecode(value as String);
          break;
      }
    }
    return builder.build();
  }

  static Jwk fromKeyPair(KeyPair keyPair) {
    if (keyPair is EcKeyPairData) {
      final crv = <KeyPairType, String>{
        KeyPairType.p256: 'P-256',
        KeyPairType.p384: 'P-384',
        KeyPairType.p521: 'P-521',
      }[keyPair.type];
      if (crv != null) {
        return Jwk(
          kty: 'EC',
          crv: crv,
          d: keyPair.d,
          x: keyPair.x,
          y: keyPair.y,
        );
      }
    } else if (keyPair is SimpleKeyPairData) {
      final crv = const <KeyPairType, String>{
        KeyPairType.ed25519: 'Ed25519',
        KeyPairType.x25519: 'X25519',
      }[keyPair.type];
      if (crv != null) {
        return Jwk(
          kty: 'EC',
          crv: crv,
          x: keyPair.bytes,
        );
      }
    } else if (keyPair is RsaKeyPairData) {
      return Jwk(
        kty: 'RSA',
        e: keyPair.e,
        d: keyPair.d,
        dp: keyPair.dp,
        dq: keyPair.dq,
        n: keyPair.n,
        p: keyPair.p,
        q: keyPair.q,
        qi: keyPair.qi,
      );
    }
    throw ArgumentError.value(keyPair);
  }

  static Jwk fromPublicKey(PublicKey publicKey) {
    if (publicKey is EcPublicKey) {
      final crv = const <KeyPairType, String>{
        KeyPairType.p256: 'P-256',
        KeyPairType.p384: 'P-384',
        KeyPairType.p521: 'P-521',
      }[publicKey.type];
      if (crv != null) {
        return Jwk(
          kty: 'EC',
          crv: crv,
          x: publicKey.x,
        );
      }
    } else if (publicKey is SimplePublicKey) {
      final crv = <KeyPairType, String>{
        KeyPairType.ed25519: 'Ed25519',
        KeyPairType.x25519: 'X25519',
      }[publicKey.type];
      if (crv != null) {
        return Jwk(
          kty: 'EC',
          crv: crv,
          x: publicKey.bytes,
        );
      }
    } else if (publicKey is RsaPublicKey) {
      return Jwk(
        kty: 'RSA',
        e: publicKey.e,
        n: publicKey.n,
      );
    }
    throw ArgumentError.value(publicKey);
  }

  static Future<Jwk> fromSecretKey(SecretKey secretKey,
      {required Cipher cipher}) async {
    final data = await secretKey.extract();
    if (cipher is AesCbc || cipher is AesCtr || cipher is AesGcm) {
      return Jwk(
        kty: 'OCK',
        alg: 'A${data.bytes.length * 8}KW',
        x: data.bytes,
      );
    }
    if (cipher is Xchacha20) {
      return Jwk(
        kty: 'OCK',
        alg: 'XC20KW',
        x: data.bytes,
      );
    }
    throw ArgumentError.value(cipher, 'cipher', 'cipher');
  }

  /// Constructs a private key from encoded JSON tree.
  static Jwk fromUtf8(List<int> bytes) {
    return fromJson(json.decode(utf8.decode(bytes)) as Map);
  }

  static List<int> _base64UriDecode(String s) {
    return const Base64Codec.urlSafe().decode(s);
  }

  static String _base64UriEncode(List<int> bytes) {
    return const Base64Codec.urlSafe().encode(bytes);
  }
}

class JwkBuilder {
  String? alg;
  String? crv;
  String? cty;
  List<int>? d;
  List<int>? dp;
  List<int>? dq;
  List<int>? e;
  String? keyOps;
  String? kid;
  String? kty;
  List<int>? n;
  List<int>? p;
  List<int>? q;
  List<int>? qi;
  String? use;
  List<int>? x;
  List<int>? x5c;
  List<int>? x5t;
  String? x5u;
  List<int>? y;

  @override
  int get hashCode => build().hashCode;

  @override
  bool operator ==(other) => other is JwkBuilder && build() == other.build();

  Jwk build() {
    return Jwk(
      alg: alg,
      crv: crv,
      cty: cty,
      e: e,
      d: d,
      dp: dp,
      dq: dq,
      keyOps: keyOps,
      kid: kid,
      kty: kty,
      n: n,
      p: p,
      q: q,
      qi: qi,
      use: use,
      x: x,
      x5c: x5c,
      x5t: x5t,
      x5u: x5u,
      y: y,
    );
  }
}

/// JWK key set.
class JwkSet {
  final List<Jwk> keys;

  const JwkSet(this.keys);

  @override
  int get hashCode => const ListEquality<Jwk>().hash(keys);

  @override
  bool operator ==(other) =>
      other is JwkSet && const ListEquality<Jwk>().equals(keys, other.keys);

  Map<String, Object?> toJson() {
    return {'keys': keys.map((e) => e.toJson()).toList()};
  }
}
