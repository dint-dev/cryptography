// Copyright 2023 Gohilla.
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
import 'package:cryptography_plus/dart.dart';
import 'package:test/test.dart';

import '../hex.dart';

void testHkdf() {
  group('Hkdf:', () {
    group('${Cryptography.instance.runtimeType}:', () {
      _main();
    });
    if (!identical(Cryptography.instance, DartCryptography.defaultInstance)) {
      group('DartCryptography:', () {
        setUp(() {
          Cryptography.instance = DartCryptography.defaultInstance;
        });
        _main();
      });
    }
    if (BrowserCryptography.isSupported) {
      group('BrowserCryptography:', () {
        setUp(() {
          Cryptography.instance = BrowserCryptography.defaultInstance;
        });
        _main();
      });
    }
  });
}

void _main() {
  test('Test case #1: Hkdf-Hmac-Sha256', () async {
    // Test vectors from RFC 5869:
    // https://tools.ietf.org/html/rfc5869

    final secretKey = SecretKey(hexToBytes(
      '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
    ));
    final nonce = hexToBytes(
      '000102030405060708090a0b0c',
    );
    final info = hexToBytes(
      'f0f1f2f3f4f5f6f7f8f9',
    );
    const length = 42;
    final expectedBytes = hexToBytes(
      '3cb25f25faacd57a90434f64d0362f2a'
      '2d2d0a90cf1a5a4c5db02d56ecc4c5bf'
      '34007208d5b887185865',
    );

    // End of test vectors

    final hkdf = Hkdf(
      hmac: Hmac(Sha256()),
      outputLength: length,
    );
    final actual = await hkdf.deriveKey(
      secretKey: secretKey,
      nonce: nonce,
      info: info,
    );
    expect(
      hexFromBytes(actual.bytes),
      hexFromBytes(expectedBytes),
    );
  });

  test('Test case #2: Hkdf-Hmac-Sha256', () async {
    // Test vectors from RFC 5869:
    // https://tools.ietf.org/html/rfc5869

    final secretKeyBytes = hexToBytes(
      '000102030405060708090a0b0c0d0e0f'
      '101112131415161718191a1b1c1d1e1f'
      '202122232425262728292a2b2c2d2e2f'
      '303132333435363738393a3b3c3d3e3f'
      '404142434445464748494a4b4c4d4e4f',
    );
    final nonce = hexToBytes(
      '606162636465666768696a6b6c6d6e6f'
      '707172737475767778797a7b7c7d7e7f'
      '808182838485868788898a8b8c8d8e8f'
      '909192939495969798999a9b9c9d9e9f'
      'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf',
    );
    final info = hexToBytes(
      'b0b1b2b3b4b5b6b7b8b9babbbcbdbebf'
      'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf'
      'd0d1d2d3d4d5d6d7d8d9dadbdcdddedf'
      'e0e1e2e3e4e5e6e7e8e9eaebecedeeef'
      'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
    );
    const length = 82;
    final expectedBytes = hexToBytes(
      'b11e398dc80327a1c8e7f78c596a4934'
      '4f012eda2d4efad8a050cc4c19afa97c'
      '59045a99cac7827271cb41c65e590e09'
      'da3275600c2f09b8367793a9aca3db71'
      'cc30c58179ec3e87c14c01d5c1f3434f'
      '1d87',
    );

    // End of test vectors

    final hkdf = Hkdf(
      hmac: Hmac(Sha256()),
      outputLength: length,
    );
    final actual = await hkdf.deriveKey(
      secretKey: SecretKey(secretKeyBytes),
      nonce: nonce,
      info: info,
    );
    expect(
      hexFromBytes(actual.bytes),
      hexFromBytes(expectedBytes),
    );
  });
}
