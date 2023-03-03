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

import 'dart:convert';

import 'package:jwk/jwk.dart';
import 'package:test/test.dart';

void main() {
  group('AES', () {
    test('fromJson / toJson', () {
      final json = <String, Object>{
        'kty': 'OCT',
        'alg': 'A128KW',
        'k': base64Url.encode([1, 2, 3]),
      };
      final key = Jwk.fromJson(json);
      expect(key.kty, 'OCT');
      expect(key.alg, 'A128KW');
      expect(key.k, [1, 2, 3]);
      expect(key.toJson(), json);
    });
  });

  group('Chacha20', () {
    test('fromJson / toJson', () {
      final json = <String, Object>{
        'kty': 'OCT',
        'alg': 'C20',
        'k': base64Url.encode([1, 2, 3]),
      };
      final key = Jwk.fromJson(json);
      expect(key.toJson(), json);
    });
  });

  group('Xchacha20', () {
    test('fromJson / toJson', () {
      final json = <String, Object>{
        'kty': 'OCT',
        'alg': 'XC20',
        'x': base64Url.encode([1, 2, 3]),
      };
      final key = Jwk.fromJson(json);
      expect(key.toJson(), json);
    });
  });

  group('P-256 private key', () {
    final json = <String, Object>{
      'kty': 'EC',
      'crv': 'P-256',
      'd': base64Url.encode([1]),
      'x': base64Url.encode([2]),
      'y': base64Url.encode([3]),
    };

    test('fromJson / toJson', () {
      final key = Jwk.fromJson(json);
      expect(key.toJson(), json);
    });

    test('toKeyPair() / fromKeyPair()', () async {
      final jwk = Jwk.fromJson(json);
      final keyPair = jwk.toKeyPair();
      final jwkFromKeyPair = await Jwk.fromKeyPair(keyPair);
      expect(jwkFromKeyPair.kty, 'EC');
      expect(jwkFromKeyPair.crv, 'P-256');
      expect(jwkFromKeyPair.d, [1]);
      expect(jwkFromKeyPair.x, [2]);
      expect(jwkFromKeyPair.y, [3]);
      expect(jwkFromKeyPair.toJson(), json);
    });
  });

  group('P-256 public key', () {
    final json = <String, Object>{
      'crv': 'P-256',
      'kty': 'EC',
      'x': base64Url.encode([1]),
      'y': base64Url.encode([2]),
    };

    test('fromJson / toJson', () {
      final key = Jwk.fromJson(json);
      expect(key.x, [1]);
      expect(key.y, [2]);
      expect(key.toJson(), json);
    });

    test('toPublicKey() / fromPublicKey()', () {
      final jwk = Jwk.fromJson(json);
      final publicKey = jwk.toPublicKey()!;
      final jwkFromPublicKey = Jwk.fromPublicKey(publicKey);
      expect(jwkFromPublicKey.x, [1]);
      expect(jwkFromPublicKey.y, [2]);
      expect(jwkFromPublicKey.toJson(), json);
    });
  });

  group('RSA private key', () {
    final json = <String, Object>{
      'd': base64Url.encode([1]),
      'dp': base64Url.encode([2]),
      'dq': base64Url.encode([3]),
      'e': base64Url.encode([4]),
      'kty': 'RSA',
      'n': base64Url.encode([5]),
      'p': base64Url.encode([6]),
      'q': base64Url.encode([7]),
      'qi': base64Url.encode([8]),
    };

    test('fromJson / toJson', () {
      final jwk = Jwk.fromJson(json);
      expect(jwk.toJson(), json);
    });

    test('toKeyPair() / fromKeyPair()', () async {
      final jwk = Jwk.fromJson(json);
      final keyPair = jwk.toKeyPair();
      final jwkFromKeyPair = await Jwk.fromKeyPair(keyPair);
      expect(jwkFromKeyPair.toJson(), json);
    });
  });

  group('RSA public key', () {
    final json = <String, Object>{
      'kty': 'RSA',
      'n': base64Url.encode([1]),
      'e': base64Url.encode([2]),
    };

    test('fromJson / toJson', () {
      final key = Jwk.fromJson(json);
      expect(key.toJson(), json);
    });

    test('toPublicKey() / fromPublicKey()', () {
      final jwk = Jwk.fromJson(json);
      final publicKey = jwk.toPublicKey()!;
      final jwkFromPublicKey = Jwk.fromPublicKey(publicKey);
      expect(jwkFromPublicKey.toJson(), json);
    });
  });
}
