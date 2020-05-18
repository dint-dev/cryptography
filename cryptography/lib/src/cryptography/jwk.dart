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
import 'package:meta/meta.dart';

/// A [JWK](https://tools.ietf.org/html/rfc7517) (RFC 7517: JSON Web Key)
/// private key.
class JwkPrivateKey extends PrivateKey {
  final List<int> d;
  final List<int> x;
  final List<int> y;

  JwkPrivateKey({
    @required this.d,
    @required this.x,
    @required this.y,
  })  : assert(d != null),
        assert(x != null),
        assert(y != null),
        super.constructor();

  /// Constructs a private key.
  static Future<JwkPrivateKey> from(PrivateKey privateKey) async {
    if (privateKey is JwkPrivateKey) {
      return privateKey;
    }
    return fromBytes(await privateKey.extract());
  }

  /// Constructs a private key.
  static JwkPrivateKey fromSync(PrivateKey privateKey) {
    if (privateKey is JwkPrivateKey) {
      return privateKey;
    }
    return fromBytes(privateKey.extractSync());
  }

  /// Constructs a private key from encoded JSON tree.
  static JwkPrivateKey fromBytes(List<int> bytes) {
    return fromJson(json.fuse(utf8).decode(bytes) as Map<String, Object>);
  }

  /// Constructs a private key from decoded JSON tree.
  static JwkPrivateKey fromJson(Map<String, Object> jwk) {
    Uint8List d;
    Uint8List x;
    Uint8List y;
    for (var entry in jwk.entries) {
      final key = entry.key;
      final value = entry.value;
      switch (key) {
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
    return JwkPrivateKey(
      d: d,
      x: x,
      y: y,
    );
  }

  /// Converts to JSON.
  Map<String, Object> toJson() {
    return <String, Object>{
      'd': base64UrlEncode(d),
      'x': base64UrlEncode(x),
      'y': base64UrlEncode(y),
    };
  }

  @override
  List<int> extractSync() {
    return json.fuse(utf8).encode(toJson());
  }
}
