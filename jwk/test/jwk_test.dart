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

import 'package:jwk_plus/jwk_plus.dart';
import 'package:test/test.dart';

void main() {
  group('AES', () {
    test('fromJson / toJson', () {
      final json = <String, Object>{
        'kty': 'OCT',
        'alg': 'A128KW',
        'k': Jwk.base64UriEncode([1, 2, 3]),
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
        'k': Jwk.base64UriEncode([1, 2, 3]),
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
        'x': Jwk.base64UriEncode([1, 2, 3]),
      };
      final key = Jwk.fromJson(json);
      expect(key.toJson(), json);
    });
  });

  group('P-256 private key', () {
    final json = <String, Object>{
      'kty': 'EC',
      'crv': 'P-256',
      'd': Jwk.base64UriEncode([1]),
      'x': Jwk.base64UriEncode([2]),
      'y': Jwk.base64UriEncode([3]),
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
      'x': Jwk.base64UriEncode([1]),
      'y': Jwk.base64UriEncode([2]),
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
      'd': Jwk.base64UriEncode([1]),
      'dp': Jwk.base64UriEncode([2]),
      'dq': Jwk.base64UriEncode([3]),
      'e': Jwk.base64UriEncode([4]),
      'kty': 'RSA',
      'n': Jwk.base64UriEncode([5]),
      'p': Jwk.base64UriEncode([6]),
      'q': Jwk.base64UriEncode([7]),
      'qi': Jwk.base64UriEncode([8]),
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
      'n': Jwk.base64UriEncode([1]),
      'e': Jwk.base64UriEncode([2]),
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
