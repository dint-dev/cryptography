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

import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';

void main() {
  group('JwkPublicKey', () {
    test('fromJson: EC', () {
      final json = <String, Object>{
        'kty': 'EC',
        'crv': 'P-256',
        'd': base64Url.encode([1]),
        'x': base64Url.encode([2]),
        'y': base64Url.encode([3]),
      };
      final key = JwkPrivateKey.fromJson(json);
      expect(key, isA<EcJwkPrivateKey>());
    });

    test('fromJson: RSA', () {
      final json = <String, Object>{
        'kty': 'RSA',
        'n': base64Url.encode([1]),
        'e': base64Url.encode([2]),
        'd': base64Url.encode([3]),
        'p': base64Url.encode([4]),
        'q': base64Url.encode([5]),
        'dp': base64Url.encode([6]),
        'dq': base64Url.encode([7]),
        'qi': base64Url.encode([8]),
      };
      final key = JwkPrivateKey.fromJson(json);
      expect(key, isA<RsaJwkPrivateKey>());
    });
  });

  group('EcJwkPrivateKey', () {
    final key = EcJwkPrivateKey(
      crv: 'P-256',
      d: [1],
      x: [2],
      y: [3],
    );
    final json = <String, Object>{
      'kty': 'EC',
      'crv': 'P-256',
      'd': base64Url.encode([1]),
      'x': base64Url.encode([2]),
      'y': base64Url.encode([3]),
    };

    test('fromJson', () {
      expect(EcJwkPrivateKey.fromJson(json), key);
    });

    test('toJson', () {
      expect(key.toJson(), json);
    });
  });

  group('EcJwkPublicKey', () {
    final key = EcJwkPublicKey(
      crv: 'P-256',
      x: [1],
      y: [2],
    );
    final json = <String, Object>{
      'kty': 'EC',
      'crv': 'P-256',
      'x': base64Url.encode([1]),
      'y': base64Url.encode([2]),
    };

    test('fromJson', () {
      expect(EcJwkPublicKey.fromJson(json), key);
    });

    test('toJson', () {
      expect(key.toJson(), json);
    });
  });

  group('RsaJwkPrivateKey', () {
    final key = RsaJwkPrivateKey(
      n: [1],
      e: [2],
      d: [3],
      p: [4],
      q: [5],
      dp: [6],
      dq: [7],
      qi: [8],
    );
    final json = <String, Object>{
      'kty': 'RSA',
      'n': base64Url.encode([1]),
      'e': base64Url.encode([2]),
      'd': base64Url.encode([3]),
      'p': base64Url.encode([4]),
      'q': base64Url.encode([5]),
      'dp': base64Url.encode([6]),
      'dq': base64Url.encode([7]),
      'qi': base64Url.encode([8]),
    };

    test('fromJson', () {
      expect(RsaJwkPrivateKey.fromJson(json), key);
    });

    test('toJson', () {
      expect(key.toJson(), json);
    });
  });

  group('RsaJwkPublicKey', () {
    final key = RsaJwkPublicKey(
      n: [1],
      e: [2],
    );
    final json = <String, Object>{
      'kty': 'RSA',
      'n': base64Url.encode([1]),
      'e': base64Url.encode([2]),
    };

    test('fromJson', () {
      expect(RsaJwkPublicKey.fromJson(json), key);
    });

    test('toJson', () {
      expect(key.toJson(), json);
    });
  });
}
