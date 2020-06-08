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

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/src/utils.dart';
import 'package:meta/meta.dart';

/// An elliptic curve private key using JWK
/// ([RFC 7517](https://tools.ietf.org/html/rfc7517): "JSON Web Key")
/// storage format.
///
/// ## JSON representation
/// ```json
/// {
///   "kty": "EC",
///   "crv": "P-256",
///   "d": "{BYTES_IN_BASE64URI}",
///   "x": "{BYTES_IN_BASE64URI}",
///   "y": "{BYTES_IN_BASE64URI}",
/// }
/// ```
class EcJwkPrivateKey extends JwkPrivateKey {
  /// Elliptic curve parameter `crv`.
  final String crv;

  /// Elliptic curve parameter `d`.
  final List<int> d;

  /// Elliptic curve parameter `x`.
  final List<int> x;

  /// Elliptic curve parameter `y`.
  final List<int> y;

  /// Constructs a private key with elliptic curve parameters.
  EcJwkPrivateKey({
    @required this.crv,
    @required this.d,
    @required this.x,
    @required this.y,
  })  : assert(d != null),
        assert(x != null),
        assert(y != null);

  @override
  Map<String, Object> toJson() {
    return <String, Object>{
      'kty': 'EC',
      'crv': crv,
      'd': base64UrlEncode(d),
      'x': base64UrlEncode(x),
      'y': base64UrlEncode(y),
    };
  }

  @override
  EcJwkPublicKey toPublicKey() {
    return EcJwkPublicKey(
      crv: crv,
      x: x,
      y: y,
    );
  }

  /// Constructs a private key.
  static Future<EcJwkPrivateKey> from(PrivateKey privateKey) async {
    if (privateKey is JwkPrivateKey) {
      return privateKey;
    }
    return fromBytes(await privateKey.extract());
  }

  /// Constructs a private key from encoded JSON tree.
  static EcJwkPrivateKey fromBytes(List<int> bytes) {
    return fromJson(json.decode(utf8.decode(bytes)) as Map<String, Object>);
  }

  /// Constructs a private key from decoded JSON tree.
  static EcJwkPrivateKey fromJson(Map<String, Object> jwk) {
    String crv;
    Uint8List d;
    Uint8List x;
    Uint8List y;
    for (var entry in jwk.entries) {
      final key = entry.key;
      final value = entry.value;
      switch (key) {
        case 'crv':
          crv = value as String;
          break;
        case 'd':
          d = base64Url.decode(value as String);
          break;
        case 'x':
          x = base64Url.decode(value as String);
          break;
        case 'y':
          y = base64Url.decode(value as String);
          break;
      }
    }
    if (d == null) {
      throw ArgumentError('Missing property "d"');
    }
    if (x == null) {
      throw ArgumentError('Missing property "x"');
    }
    if (y == null) {
      throw ArgumentError('Missing property "y"');
    }
    return EcJwkPrivateKey(
      crv: crv,
      d: d,
      x: x,
      y: y,
    );
  }

  /// Constructs a private key.
  static JwkPrivateKey fromSync(PrivateKey privateKey) {
    if (privateKey is JwkPrivateKey) {
      return privateKey;
    }
    return fromBytes(privateKey.extractSync());
  }
}

/// An elliptic curve public key using JWK
/// ([RFC 7517](https://tools.ietf.org/html/rfc7517): "JSON Web Key")
/// storage format.
///
/// ## JSON representation
/// ```json
/// {
///   "kty": "EC",
///   "crv": "P-256",
///   "x": "{BYTES_IN_BASE64URI}",
///   "y": "{BYTES_IN_BASE64URI}",
/// }
/// ```
class EcJwkPublicKey extends JwkPublicKey {
  /// Elliptic curve parameter `crv` ("P-256", "P-384", or "P-521").
  final String crv;

  /// Elliptic curve parameter `x`.
  final List<int> x;

  /// Elliptic curve parameter `y`.
  final List<int> y;

  EcJwkPublicKey({
    @required this.crv,
    @required this.x,
    @required this.y,
  })  : assert(x != null),
        assert(y != null);

  @override
  Map<String, Object> toJson() {
    return <String, Object>{
      'kty': 'EC',
      'crv': crv,
      'x': base64Url.encode(x),
      'y': base64Url.encode(y),
    };
  }

  /// Constructs a private key from encoded JSON tree.
  static EcJwkPublicKey fromBytes(List<int> bytes) {
    return fromJson(json.decode(utf8.decode(bytes)) as Map<String, Object>);
  }

  /// Constructs a private key from decoded JSON tree.
  static EcJwkPublicKey fromJson(Map<String, Object> jwk) {
    String crv;
    Uint8List x;
    Uint8List y;
    for (var entry in jwk.entries) {
      final key = entry.key;
      final value = entry.value;
      switch (key) {
        case 'crv':
          crv = value as String;
          break;
        case 'x':
          x = base64Url.decode(value as String);
          break;
        case 'y':
          y = base64Url.decode(value as String);
          break;
      }
    }
    if (crv == null) {
      throw ArgumentError('Missing property "crv"');
    }
    if (x == null) {
      throw ArgumentError('Missing property "x"');
    }
    if (y == null) {
      throw ArgumentError('Missing property "y"');
    }
    return EcJwkPublicKey(
      crv: crv,
      x: x,
      y: y,
    );
  }
}

/// Superclass for public keys that use JWK ([RFC 7517](https://tools.ietf.org/html/rfc7517):
/// "JSON Web Key") storage format.
///
/// ## Implementations
///   * [EcJwkPrivateKey]
///   * [RsaJwkPrivateKey].
abstract class JwkPrivateKey extends PrivateKey {
  List<int> _bytes;

  JwkPrivateKey() : super.constructor();

  @override
  bool operator ==(other) =>
      other is JwkPrivateKey &&
      constantTimeBytesEquality.equals(extractSync(), other.extractSync());

  @override
  List<int> extractSync() {
    return _bytes ??= utf8.encode(json.encode(toJson()));
  }

  /// Converts to JSON.
  Map<String, Object> toJson();

  JwkPublicKey toPublicKey();

  /// Constructs a private key from the bytes.
  static JwkPrivateKey fromBytes(List<int> bytes) {
    return fromJson(json.decode(utf8.decode(bytes)) as Map<String, Object>);
  }

  /// Constructs a private key from the JSON tree.
  static JwkPrivateKey fromJson(Map<String, Object> json) {
    final kty = json['kty'];
    if (kty == 'EC') {
      return EcJwkPrivateKey.fromJson(json);
    }
    if (kty == 'RSA') {
      return RsaJwkPrivateKey.fromJson(json);
    }
    throw ArgumentError('Invalid key type: $kty');
  }
}

/// Superclass for public keys that use JWK ([RFC 7517](https://tools.ietf.org/html/rfc7517):
/// "JSON Web Key") storage format.
///
/// ## Implementations
///   * [EcJwkPublicKey]
///   * [RsaJwkPublicKey].
abstract class JwkPublicKey extends PublicKey {
  List<int> _bytes;

  JwkPublicKey() : super.constructor();

  @override
  List<int> get bytes => _bytes ??= utf8.encode(json.encode(toJson()));

  @override
  bool operator ==(other) =>
      other is JwkPublicKey &&
      constantTimeBytesEquality.equals(bytes, other.bytes);

  Map<String, Object> toJson();

  /// Constructs a private key from the bytes.
  static JwkPublicKey fromBytes(List<int> bytes) {
    return fromJson(json.fuse(utf8).decode(bytes) as Map<String, Object>);
  }

  /// Constructs a private key from the JSON tree.
  static JwkPublicKey fromJson(Map<String, Object> json) {
    final kty = json['kty'];
    if (kty == 'EC') {
      return EcJwkPublicKey.fromJson(json);
    }
    if (kty == 'RSA') {
      return RsaJwkPublicKey.fromJson(json);
    }
    throw ArgumentError('Invalid key type: $kty');
  }
}

/// An RSA private key that uses JWK ([RFC 7517](https://tools.ietf.org/html/rfc7517):
/// "JSON Web Key") storage format.
///
/// ## JSON representation
/// ```json
/// {
///   "kty": "RSA",
///   "n": "{BYTES_IN_BASE64URI}",
///   "e": "{BYTES_IN_BASE64URI}",
///   "d": "{BYTES_IN_BASE64URI}",
///   "q": "{BYTES_IN_BASE64URI}",
///   "dp": "{BYTES_IN_BASE64URI}",
///   "dq": "{BYTES_IN_BASE64URI}",
///   "qi": "{BYTES_IN_BASE64URI}",
/// }
/// ```
class RsaJwkPrivateKey extends JwkPrivateKey {
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
  final List<int> dp;

  /// RSA private key parameter `dq`.
  final List<int> dq;

  /// RSA private key parameter `qi`.
  final List<int> qi;

  /// Constructs a private key with elliptic curve parameters.
  RsaJwkPrivateKey({
    @required this.n,
    @required this.e,
    @required this.d,
    @required this.p,
    @required this.q,
    @required this.dp,
    @required this.dq,
    @required this.qi,
  })  : assert(n != null),
        assert(e != null),
        assert(d != null);

  @override
  List<int> extractSync() {
    return _bytes ??= utf8.encode(json.encode(toJson()));
  }

  @override
  Map<String, Object> toJson() {
    return <String, Object>{
      'kty': 'RSA',
      'n': base64Url.encode(n),
      'e': base64Url.encode(e),
      'd': base64Url.encode(d),
      'p': base64Url.encode(p),
      'q': base64Url.encode(q),
      'dp': base64Url.encode(dp),
      'dq': base64Url.encode(dq),
      'qi': base64Url.encode(qi),
    };
  }

  @override
  RsaJwkPublicKey toPublicKey() {
    return RsaJwkPublicKey(
      n: n,
      e: e,
    );
  }

  /// Constructs a private key from encoded JSON tree.
  static RsaJwkPrivateKey fromBytes(List<int> bytes) {
    return fromJson(json.decode(utf8.decode(bytes)) as Map<String, Object>);
  }

  /// Constructs a private key from decoded JSON tree.
  static RsaJwkPrivateKey fromJson(Map<String, Object> jwk) {
    Uint8List n;
    Uint8List e;
    Uint8List d;
    Uint8List p;
    Uint8List q;
    Uint8List dp;
    Uint8List dq;
    Uint8List qi;
    for (var entry in jwk.entries) {
      final key = entry.key;
      final value = entry.value;
      switch (key) {
        case 'n':
          n = base64Url.decode(value as String);
          break;
        case 'e':
          e = base64Url.decode(value as String);
          break;
        case 'd':
          d = base64Url.decode(value as String);
          break;
        case 'p':
          p = base64Url.decode(value as String);
          break;
        case 'q':
          q = base64Url.decode(value as String);
          break;
        case 'dp':
          dp = base64Url.decode(value as String);
          break;
        case 'dq':
          dq = base64Url.decode(value as String);
          break;
        case 'qi':
          qi = base64Url.decode(value as String);
          break;
      }
    }
    if (n == null) {
      throw ArgumentError('Missing property "n"');
    }
    if (e == null) {
      throw ArgumentError('Missing property "e"');
    }
    if (d == null) {
      throw ArgumentError('Missing property "d"');
    }
    if (p == null) {
      throw ArgumentError('Missing property "p"');
    }
    if (q == null) {
      throw ArgumentError('Missing property "q"');
    }
    return RsaJwkPrivateKey(
      n: n,
      e: e,
      d: d,
      p: p,
      q: q,
      dp: dp,
      dq: dq,
      qi: qi,
    );
  }
}

/// An RSA public key that uses JWK ([RFC 7517](https://tools.ietf.org/html/rfc7517):
/// "JSON Web Key") storage format.
///
/// ## JSON representation
/// ```json
/// {
///   "kty": "RSA",
///   "n": "{BYTES_IN_BASE64URI}",
///   "e": "{BYTES_IN_BASE64URI}",
/// }
/// ```
class RsaJwkPublicKey extends JwkPublicKey {
  /// RSA modulus.
  final List<int> n;

  /// RSA exponent.
  final List<int> e;

  RsaJwkPublicKey({
    @required this.n,
    @required this.e,
  });

  @override
  Map<String, Object> toJson() {
    return <String, Object>{
      'kty': 'RSA',
      'n': base64Url.encode(n),
      'e': base64Url.encode(e),
    };
  }

  /// Constructs a private key from encoded JSON tree.
  static RsaJwkPublicKey fromBytes(List<int> bytes) {
    return fromJson(json.decode(utf8.decode(bytes)) as Map<String, Object>);
  }

  /// Constructs a private key from decoded JSON tree.
  static RsaJwkPublicKey fromJson(Map<String, Object> jwk) {
    Uint8List n;
    Uint8List e;
    for (var entry in jwk.entries) {
      final key = entry.key;
      final value = entry.value;
      switch (key) {
        case 'n':
          n = base64Url.decode(value as String);
          break;
        case 'e':
          e = base64Url.decode(value as String);
          break;
      }
    }
    if (n == null) {
      throw ArgumentError('Missing property "n"');
    }
    if (e == null) {
      throw ArgumentError('Missing property "e"');
    }
    return RsaJwkPublicKey(
      n: n,
      e: e,
    );
  }
}
