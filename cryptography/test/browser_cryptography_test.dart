// Copyright 2019-2022 Gohilla.
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

@TestOn('chrome')
import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:cryptography_plus/dart.dart';
import 'package:cryptography_plus/src/browser/aes_cbc.dart';
import 'package:cryptography_plus/src/browser/aes_ctr.dart';
import 'package:cryptography_plus/src/browser/aes_gcm.dart';
import 'package:cryptography_plus/src/browser/hash.dart';
import 'package:cryptography_plus/src/browser/hmac.dart';
import 'package:cryptography_plus/src/browser/pbkdf2.dart';
import 'package:test/expect.dart';
import 'package:test/scaffolding.dart';

void main() {
  tearDown(() {
    BrowserCryptography.isDisabledForTesting = false;
  });

  test('isSupported', () {
    expect(BrowserCryptography.isSupported, isTrue);
    expect(BrowserCryptography.isDisabledForTesting, isFalse);
    BrowserCryptography.isDisabledForTesting = true;
    expect(BrowserCryptography.isDisabledForTesting, isTrue);
    expect(BrowserCryptography.isSupported, isFalse);
  });

  group('AES-CBC:', () {
    test('AesCbc.with128bits(...)', () {
      final algorithm = AesCbc.with128bits(macAlgorithm: MacAlgorithm.empty);
      expect(algorithm, isA<BrowserAesCbc>());
      expect(algorithm.secretKeyLength, 16);

      BrowserCryptography.isDisabledForTesting = true;
      expect(
        AesCbc.with128bits(macAlgorithm: MacAlgorithm.empty),
        isNot(isA<BrowserAesCbc>()),
      );
    });

    test('AesCbc.with192bits(...)', () {
      final algorithm = AesCbc.with192bits(macAlgorithm: MacAlgorithm.empty);
      expect(algorithm, isNot(isA<BrowserAesCbc>()));
      expect(algorithm.secretKeyLength, 24);

      BrowserCryptography.isDisabledForTesting = true;
      expect(
        AesCbc.with256bits(macAlgorithm: MacAlgorithm.empty),
        isNot(isA<BrowserAesCbc>()),
      );
    });

    test('AesCbc.with256bits(...)', () {
      final algorithm = AesCbc.with256bits(macAlgorithm: MacAlgorithm.empty);
      expect(algorithm, isA<BrowserAesCbc>());
      expect(algorithm.secretKeyLength, 32);

      BrowserCryptography.isDisabledForTesting = true;
      expect(
        AesCbc.with256bits(macAlgorithm: MacAlgorithm.empty),
        isNot(isA<BrowserAesCbc>()),
      );
    });

    test(
        'AesCbc.with256bits(..., paddingAlgorithm: somethingElse) is not BrowserAesCbc',
        () {
      final algorithm = AesCbc.with256bits(
        macAlgorithm: MacAlgorithm.empty,
        paddingAlgorithm: PaddingAlgorithm.zero,
      );
      expect(algorithm, isNot(isA<BrowserAesCtr>()));
    });
  });

  group('AES-CTR:', () {
    test('AesCtr.with128bits(...)', () {
      final algorithm = AesCtr.with128bits(macAlgorithm: MacAlgorithm.empty);
      expect(algorithm, isA<BrowserAesCtr>());

      BrowserCryptography.isDisabledForTesting = true;
      expect(
        AesCtr.with128bits(macAlgorithm: MacAlgorithm.empty),
        isNot(isA<BrowserAesCtr>()),
      );
    });

    test('AesCtr.with192bits(...) is DartAesCtr', () {
      final algorithm = AesCbc.with192bits(macAlgorithm: MacAlgorithm.empty);
      expect(algorithm, isNot(isA<BrowserAesCtr>()));
      expect(algorithm.secretKeyLength, 24);
    });

    test('AesCtr.with256bits(...)', () {
      final algorithm = AesCtr.with256bits(macAlgorithm: MacAlgorithm.empty);
      expect(algorithm, isA<BrowserAesCtr>());

      BrowserCryptography.isDisabledForTesting = true;
      expect(
        AesCtr.with256bits(macAlgorithm: MacAlgorithm.empty),
        isNot(isA<BrowserAesCtr>()),
      );
    });
  });

  group('AES-GCM:', () {
    test('AesGcm.with128bits(...)', () {
      final algorithm = AesGcm.with128bits();
      expect(algorithm, isA<BrowserAesGcm>());
    });

    test('AesGcm.with128bits(...), Web Cryptography disabled', () {
      BrowserCryptography.isDisabledForTesting = true;
      final algorithm = AesGcm.with128bits();
      expect(algorithm, isA<DartAesGcm>());
      expect(algorithm.secretKeyLength, 16);
    });

    test('AesGcm.with192bits(...)', () {
      final algorithm = AesGcm.with192bits();
      expect(algorithm, isNot(isA<BrowserAesGcm>()));
      expect(algorithm.secretKeyLength, 24);
    });

    test('AesGcm.with256bits(...)', () {
      final algorithm = AesGcm.with256bits();
      expect(algorithm, isA<BrowserAesGcm>());
      expect(algorithm.secretKeyLength, 32);
    });

    test('AesGcm.with256bits(...), Web Cryptography disabled', () {
      BrowserCryptography.isDisabledForTesting = true;
      expect(AesGcm.with256bits(), isNot(isA<BrowserAesGcm>()));
    });
  });

  test('Sha1:', () {
    expect(Sha1(), isA<BrowserSha1>());

    BrowserCryptography.isDisabledForTesting = true;
    expect(Sha1(), isNot(isA<BrowserSha1>()));
  });

  test('Sha256:', () {
    expect(Sha256(), isA<BrowserSha256>());

    BrowserCryptography.isDisabledForTesting = true;
    expect(Sha256(), isNot(isA<BrowserSha256>()));
  });

  test('Sha384:', () {
    expect(Sha384(), isA<BrowserSha384>());

    BrowserCryptography.isDisabledForTesting = true;
    expect(Sha384(), isNot(isA<BrowserSha384>()));
  });

  test('Sha512:', () {
    expect(Sha512(), isA<BrowserSha512>());

    BrowserCryptography.isDisabledForTesting = true;
    expect(Sha512(), isNot(isA<BrowserSha512>()));
  });

  group('HMAC:', () {
    test('Hmac(Sha224())', () {
      final algorithm = Hmac(Sha224());
      expect(algorithm, isNot(isA<BrowserHmac>()));
    });

    test('Hmac(Sha256())', () {
      final algorithm = Hmac(Sha256());
      expect(algorithm, isA<BrowserHmac>());
      expect(algorithm.hashAlgorithm, isA<Sha256>());
    });

    test('Hmac(Sha256()), Web Cryptography disabled', () {
      BrowserCryptography.isDisabledForTesting = true;

      final algorithm = Hmac(Sha256());
      expect(algorithm, isNot(isA<BrowserHmac>()));
      expect(algorithm.hashAlgorithm, isA<Sha256>());
    });

    test('Hmac(Sha384())', () {
      final algorithm = Hmac(Sha384());
      expect(algorithm, isA<BrowserHmac>());
      expect(algorithm.hashAlgorithm, isA<Sha384>());
    });

    test('Hmac(Sha384()), Web Cryptography disabled', () {
      BrowserCryptography.isDisabledForTesting = true;

      final algorithm = Hmac(Sha384());
      expect(algorithm, isNot(isA<BrowserHmac>()));
      expect(algorithm.hashAlgorithm, isA<Sha384>());
    });

    test('Hmac(Sha512())', () {
      final algorithm = Hmac(Sha512());
      expect(algorithm, isA<BrowserHmac>());
      expect(algorithm.hashAlgorithm, isA<Sha512>());
    });

    test('Hmac(Sha512()), Web cryptography disabled', () {
      BrowserCryptography.isDisabledForTesting = true;

      final algorithm = Hmac(Sha512());
      expect(algorithm, isNot(isA<BrowserHmac>()));
    });
  });

  group('Pbkdf2:', () {
    test('using Hmac(Sha256())', () {
      final algorithm = Pbkdf2(
        macAlgorithm: Hmac(Sha256()),
        iterations: 10,
        bits: 128,
      );
      expect(algorithm, isA<BrowserPbkdf2>());
      expect(algorithm.iterations, 10);
      expect(algorithm.bits, 128);
    });

    test('using Hmac(Sha256()), Web Cryptography disabled', () {
      BrowserCryptography.isDisabledForTesting = true;

      final algorithm = Pbkdf2(
        macAlgorithm: Hmac(Sha256()),
        iterations: 10,
        bits: 128,
      );
      expect(algorithm, isNot(isA<BrowserPbkdf2>()));
      expect(algorithm.iterations, 10);
      expect(algorithm.bits, 128);
    });

    test('using Hmac(Sha512())', () {
      final algorithm = Pbkdf2(
        macAlgorithm: Hmac(Sha512()),
        iterations: 10,
        bits: 128,
      );
      expect(algorithm, isA<BrowserPbkdf2>());
      expect(algorithm.iterations, 10);
      expect(algorithm.bits, 128);
    });
  });
}
