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

/// JWK (JSON Web Key) encoding and decoding.
///
/// See documentation for the class [Jwk].
library jwk_plus;

import 'dart:convert';
import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:cryptography_plus/dart.dart';

/// A JWK ([RFC 7517](https://tools.ietf.org/html/rfc7517): "JSON Web Key")
/// formatted cryptographic key.
///
/// ## Examples of JSON representation
/// ### AES 128 bit key
/// ```json
/// final key = Jwt.fromJson({
///   "kty": "OCT",
///   "alg":"A128KW",
///   "k": "{BYTES_IN_BASE64URI}",
/// });
/// ```
///
/// ### Ed25519 private key
/// ```json
/// final key = Jwt.fromJson({
///   "kty": "OKP",
///   "crv": "Ed25519",
///   "d": "{BYTES_IN_BASE64URI}",
///   "x": "{BYTES_IN_BASE64URI}",
/// });
/// ```
///
/// ### P-256 private key
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
/// ## RSA private key
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
  ///   * "OCT" (Octet sequence)
  ///   * "EC" (Elliptic Key)
  ///   * "OKP" (Octet Key Pair)
  ///   * "RSA" (RSA key)
  final String? kty;

  /// Algorithm of the key.
  final String? alg;

  /// Parameter `cty`.
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

  /// Parameter `d`.
  final List<int>? d;

  /// RSA private key parameter `dp`.
  final List<int>? dp;

  /// RSA private key parameter `dq`.
  final List<int>? dq;

  /// RSA exponent. This is public information.
  final List<int>? e;

  /// Parameter `k`.
  final List<int>? k;

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
    this.k,
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
      Object.hashAll(x ?? const []) ^
      Object.hashAll(y ?? const []);

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

  /// Constructs [JwkBuilder] from this object.
  JwkBuilder toBuilder() {
    return JwkBuilder()
      ..alg = alg
      ..crv = crv
      ..cty = cty
      ..d = d
      ..dp = dp
      ..dq = dq
      ..e = e
      ..k = k
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

  /// Constructs a JSON object from this object.
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
        result['d'] = base64UriEncode(value);
      }
    }
    {
      final value = dp;
      if (value != null) {
        result['dp'] = base64UriEncode(value);
      }
    }
    {
      final value = dq;
      if (value != null) {
        result['dq'] = base64UriEncode(value);
      }
    }
    {
      final value = e;
      if (value != null) {
        result['e'] = base64UriEncode(value);
      }
    }
    {
      final value = k;
      if (value != null) {
        result['k'] = base64UriEncode(value);
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
        result['n'] = base64UriEncode(value);
      }
    }
    {
      final value = p;
      if (value != null) {
        result['p'] = base64UriEncode(value);
      }
    }
    {
      final value = q;
      if (value != null) {
        result['q'] = base64UriEncode(value);
      }
    }
    {
      final value = qi;
      if (value != null) {
        result['qi'] = base64UriEncode(value);
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
        result['x'] = base64UriEncode(value);
      }
    }
    {
      final value = x5c;
      if (value != null) {
        result['x5c'] = base64UriEncode(value);
      }
    }
    {
      final value = x5t;
      if (value != null) {
        result['x5t'] = base64UriEncode(value);
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
        result['y'] = base64UriEncode(value);
      }
    }
    return result;
  }

  /// Constructs a [KeyPair] from this [Jwk].
  KeyPair toKeyPair() {
    switch (kty) {
      case 'EC':
        final type = const <String, KeyPairType>{
          'P-256': KeyPairType.p256,
          'secp256k1': KeyPairType.p256k,
          'P-384': KeyPairType.p384,
          'P-521': KeyPairType.p521,
        }[crv];
        if (type == null) {
          throw StateError('Unsupported "crv": "$crv"');
        }
        return EcKeyPairData(
          d: Uint8List.fromList(d ?? const <int>[]),
          x: Uint8List.fromList(x ?? const <int>[]),
          y: Uint8List.fromList(y ?? const <int>[]),
          type: type,
        );

      case 'OKP':
        if (crv == 'Ed25519') {
          final d = this.d!;
          return _LazySimpleKeyPair(
            d,
            () async {
              final keyPair = await Ed25519().newKeyPairFromSeed(d);
              return await keyPair.extractPublicKey();
            },
            KeyPairType.ed25519,
          );
        }
        if (crv == 'X25519') {
          final d = this.d!;
          return _LazySimpleKeyPair(
            d,
            () async {
              final keyPair = await X25519().newKeyPairFromSeed(d);
              return await keyPair.extractPublicKey();
            },
            KeyPairType.x25519,
          );
        }
        throw StateError('Unsupported "crv": "$crv"');

      case 'RSA':
        return RsaKeyPairData(
          e: Uint8List.fromList(e ?? const <int>[]),
          d: Uint8List.fromList(d ?? const <int>[]),
          dp: Uint8List.fromList(dp ?? const <int>[]),
          dq: Uint8List.fromList(dq ?? const <int>[]),
          n: Uint8List.fromList(n ?? const <int>[]),
          p: Uint8List.fromList(p ?? const <int>[]),
          q: Uint8List.fromList(q ?? const <int>[]),
          qi: Uint8List.fromList(qi ?? const <int>[]),
        );

      default:
        throw StateError('Not a key pair (kty: $kty)');
    }
  }

  /// Constructs a [PublicKey] from this [Jwk].
  PublicKey? toPublicKey() {
    switch (kty) {
      case 'EC':
        final type = const <String, KeyPairType>{
          'P-256': KeyPairType.p256,
          'secp256k1': KeyPairType.p256k,
          'P-384': KeyPairType.p384,
          'P-521': KeyPairType.p521,
        }[crv];
        if (type == null) {
          throw StateError('Unsupported "crv": "$crv"');
        }
        return EcPublicKey(
          x: Uint8List.fromList(x ?? const <int>[]),
          y: Uint8List.fromList(y ?? const <int>[]),
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
          Uint8List.fromList(x ?? const <int>[]),
          type: type,
        );

      case 'RSA':
        return RsaPublicKey(
          e: Uint8List.fromList(e ?? const <int>[]),
          n: Uint8List.fromList(n ?? const <int>[]),
        );
    }
    return null;
  }

  /// Constructs a [SecretKey] from this [Jwk].
  SecretKey toSecretKey() {
    switch (kty) {
      case 'OCT':
        return SecretKey(
          Uint8List.fromList(k ?? const <int>[]),
        );

      default:
        throw StateError('Not a secret key (kty: $kty)');
    }
  }

  /// Encodes the output of [toJson()] as a string.
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
          builder.d = base64UriDecode(value as String);
          break;
        case 'dp':
          builder.dp = base64UriDecode(value as String);
          break;
        case 'dq':
          builder.dq = base64UriDecode(value as String);
          break;
        case 'e':
          builder.e = base64UriDecode(value as String);
          break;
        case 'k':
          builder.k = base64UriDecode(value as String);
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
          builder.n = base64UriDecode(value as String);
          break;
        case 'p':
          builder.p = base64UriDecode(value as String);
          break;
        case 'q':
          builder.q = base64UriDecode(value as String);
          break;
        case 'qi':
          builder.qi = base64UriDecode(value as String);
          break;
        case 'use':
          builder.use = value as String;
          break;
        case 'x':
          builder.x = base64UriDecode(value as String);
          break;
        case 'x5c':
          builder.x5c = base64UriDecode(value as String);
          break;
        case 'x5t':
          builder.x5t = base64UriDecode(value as String);
          break;
        case 'x5u':
          builder.x5u = value as String;
          break;
        case 'y':
          builder.y = base64UriDecode(value as String);
          break;
      }
    }
    return builder.build();
  }

  /// Converts [KeyPair] to [Jwk].
  static Future<Jwk> fromKeyPair(KeyPair keyPair) async {
    keyPair = await keyPair.extract();
    if (keyPair is EcKeyPairData) {
      final crv = const <KeyPairType, String>{
        KeyPairType.p256: 'P-256',
        KeyPairType.p256k: 'secp256k1',
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
          kty: 'OKP',
          crv: crv,
          d: keyPair.bytes,
          x: keyPair.publicKey.bytes,
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

  /// Converts [PublicKey] into [Jwk].
  static Jwk fromPublicKey(PublicKey publicKey) {
    if (publicKey is EcPublicKey) {
      final crv = const <KeyPairType, String>{
        KeyPairType.p256: 'P-256',
        KeyPairType.p256k: 'secp256k1',
        KeyPairType.p384: 'P-384',
        KeyPairType.p521: 'P-521',
      }[publicKey.type];
      if (crv != null) {
        return Jwk(
          kty: 'EC',
          crv: crv,
          x: publicKey.x,
          y: publicKey.y,
        );
      }
    } else if (publicKey is SimplePublicKey) {
      final crv = const <KeyPairType, String>{
        KeyPairType.ed25519: 'Ed25519',
        KeyPairType.x25519: 'X25519',
      }[publicKey.type];
      if (crv != null) {
        return Jwk(
          kty: 'OKP',
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

  /// Converts [SecretKey] into [Jwk].
  static Future<Jwk> fromSecretKey(
    SecretKey secretKey, {
    required Cipher cipher,
  }) async {
    final data = await secretKey.extract();
    if (cipher is AesCbc || cipher is AesCtr || cipher is AesGcm) {
      return Jwk(
        kty: 'OCT',
        alg: 'A${data.bytes.length * 8}KW',
        k: data.bytes,
      );
    }
    if (cipher is Chacha20 &&
        cipher.macAlgorithm is DartChacha20Poly1305AeadMacAlgorithm) {
      return Jwk(
        kty: 'OCT',
        alg: 'C20PKW',
        k: data.bytes,
      );
    }
    if (cipher is Xchacha20 &&
        cipher.macAlgorithm is DartChacha20Poly1305AeadMacAlgorithm) {
      return Jwk(
        kty: 'OCT',
        alg: 'XC20KW',
        k: data.bytes,
      );
    }
    throw ArgumentError.value(cipher, 'cipher');
  }

  /// Constructs a private key from encoded JSON tree.
  static Jwk fromUtf8(List<int> bytes) {
    return fromJson(json.decode(utf8.decode(bytes)) as Map);
  }

  static List<int> base64UriDecode(String s) {
    return const Base64Codec.urlSafe()
        .decode(s + '=' * ((4 - s.length % 4) % 4));
  }

  static String base64UriEncode(List<int> bytes) {
    return const Base64Codec.urlSafe().encode(bytes).split('=').first;
  }
}

/// A builder class [Jwk].
class JwkBuilder {
  String? alg;
  String? crv;
  String? cty;
  List<int>? d;
  List<int>? dp;
  List<int>? dq;
  List<int>? e;
  List<int>? k;
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

  /// Builds an immutable [Jwk] instance.
  Jwk build() {
    return Jwk(
      alg: alg,
      crv: crv,
      cty: cty,
      e: e,
      d: d,
      dp: dp,
      dq: dq,
      k: k,
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

  /// Parses JSON tree into a [JwkSet].
  factory JwkSet.fromJson(Map<String, Object?> json) {
    return JwkSet((json['keys'] as List)
        .map((e) => Jwk.fromJson(e as Map<String, Object?>))
        .toList());
  }

  @override
  int get hashCode => const ListEquality<Jwk>().hash(keys);

  @override
  bool operator ==(other) =>
      other is JwkSet && const ListEquality<Jwk>().equals(keys, other.keys);

  /// Converts [JwkSet] into a JSON tree.
  Map<String, Object?> toJson() {
    return {'keys': keys.map((e) => e.toJson()).toList()};
  }
}

class _LazySimpleKeyPair extends SimpleKeyPair {
  final List<int> _bytes;
  final Future<SimplePublicKey> Function() _publicKeyFunction;
  final KeyPairType type;
  Future<SimplePublicKey>? _publicKeyFuture;

  _LazySimpleKeyPair(
    this._bytes,
    this._publicKeyFunction,
    this.type,
  ) : super.constructor();

  @override
  Future<SimpleKeyPairData> extract() async {
    if (hasBeenDestroyed) {
      throw StateError('Key has been destroyed');
    }
    return SimpleKeyPairData(
      _bytes,
      publicKey: await extractPublicKey(),
      type: type,
    );
  }

  @override
  Future<List<int>> extractPrivateKeyBytes() async {
    if (hasBeenDestroyed) {
      throw StateError('Key has been destroyed');
    }
    return _bytes;
  }

  @override
  Future<SimplePublicKey> extractPublicKey() {
    return _publicKeyFuture ??= _publicKeyFunction();
  }
}
