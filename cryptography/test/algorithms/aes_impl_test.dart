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

import 'dart:typed_data';

import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:cryptography_plus/src/_internal/hex.dart';
import 'package:cryptography_plus/src/dart/aes_impl.dart' as aes;
import 'package:cryptography_plus/src/dart/aes_impl_constants.dart' as constants;
import 'package:test/expect.dart';
import 'package:test/scaffolding.dart';

void main() {
  test('AES S-Box constants', () {
    for (var i = 0; i < 256; i++) {
      expect(constants.sInv[constants.s[i]], i);
      expect(constants.s[constants.sInv[i]], i);
    }
  });

  test('AES decryption constants', () {
    for (var i = 0; i < 256; i++) {
      final s = constants.sInv[i];
      var v = _mul(s, 0xe) << 24 |
          _mul(s, 0x9) << 16 |
          _mul(s, 0xd) << 8 |
          _mul(s, 0xb);
      expect(constants.d0[i], v);

      v = (0xFFFFFFFF & (v << 24)) | v >> 8;
      expect(constants.d1[i], v);

      v = (0xFFFFFFFF & (v << 24)) | v >> 8;
      expect(constants.d2[i], v);

      v = (0xFFFFFFFF & (v << 24)) | v >> 8;
      expect(constants.d3[i], v);
    }
  });

  test('expandForEncrypting', () {
    // From appendix of the AES specification:
    // https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf
    final key = hexToBytes(
      '2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c',
    );
    final expandedKey = aes.aesExpandKeyForEncrypting(SecretKeyData(key));

    _expectHex(expandedKey[0], 0x2b7e1516);
    _expectHex(expandedKey[1], 0x28aed2a6);
    _expectHex(expandedKey[2], 0xabf71588);
    _expectHex(expandedKey[3], 0x09cf4f3c);

    _expectHex(expandedKey[4], 0xa0fafe17);
    _expectHex(expandedKey[5], 0x88542cb1);
    _expectHex(expandedKey[6], 0x23a33939);
    _expectHex(expandedKey[7], 0x2a6c7605);

    _expectHex(expandedKey[40], 0xd014f9a8);
    _expectHex(expandedKey[41], 0xc9ee2589);
    _expectHex(expandedKey[42], 0xe13f0cc8);
    _expectHex(expandedKey[43], 0xb6630ca6);
  });

  test('expandForDecrypting', () {
    // From appendix of the AES specification:
    // https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf
    final key = hexToBytes(
      '000102030405060708090a0b0c0d0e0f',
    );
    final expandedKey = aes.aesExpandKeyForDecrypting(SecretKeyData(key));

    _expectHex(expandedKey[0], 0x13111d7f);
    _expectHex(expandedKey[1], 0xe3944a17);
    _expectHex(expandedKey[2], 0xf307a78b);
    _expectHex(expandedKey[3], 0x4d2b30c5);

    _expectHex(expandedKey[4], 0x13aa29be);
    _expectHex(expandedKey[5], 0x9c8faff6);
    _expectHex(expandedKey[6], 0xf770f580);
    _expectHex(expandedKey[7], 0x00f7bf03);

    _expectHex(expandedKey[40], 0x00010203);
  });

  group('AES block function:', () {
    group('128-bit key:', () {
      // From appendix of the AES specification:
      // https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf
      final clearText = hexToBytes(
        '00112233445566778899aabbccddeeff',
      );
      final key = hexToBytes(
        '000102030405060708090a0b0c0d0e0f',
      );
      final cipherText = hexToBytes(
        '69c4e0d86a7b0430d8cdb78070b4c55a',
      );

      test('encrypt', () {
        final encrypted = Uint32List(cipherText.length);
        aes.aesEncryptBlock(
          encrypted,
          0,
          aes.aesBlocksFromBytes(clearText),
          0,
          aes.aesExpandKeyForEncrypting(SecretKeyData(key)),
        );
        expect(
          hexFromBytes(Uint8List.view(encrypted.buffer, 0, cipherText.length)),
          hexFromBytes(cipherText),
        );
      });

      test('decrypt', () {
        final decrypted = Uint32List(cipherText.length);
        aes.aesDecryptBlock(
          decrypted,
          0,
          aes.aesBlocksFromBytes(cipherText),
          0,
          aes.aesExpandKeyForDecrypting(SecretKeyData(key)),
        );
        expect(
          hexFromBytes(Uint8List.view(decrypted.buffer, 0, cipherText.length)),
          hexFromBytes(clearText),
        );
      });
    });

    group('192-bit key:', () {
      // From appendix of the AES specification:
      // https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf
      final clearText = hexToBytes(
        '00112233445566778899aabbccddeeff',
      );
      final key = hexToBytes(
        '000102030405060708090a0b0c0d0e0f1011121314151617',
      );
      final cipherText = hexToBytes(
        'dda97ca4864cdfe06eaf70a0ec0d7191',
      );

      test('encrypt', () {
        final encrypted = Uint32List(cipherText.length);
        encrypted.setAll(0, clearText);
        aes.aesEncryptBlock(
          encrypted,
          0,
          aes.aesBlocksFromBytes(clearText),
          0,
          aes.aesExpandKeyForEncrypting(SecretKeyData(key)),
        );
        expect(
          hexFromBytes(Uint8List.view(encrypted.buffer, 0, cipherText.length)),
          hexFromBytes(cipherText),
        );
      });

      test('decrypt', () {
        final decrypted = Uint32List(cipherText.length);
        aes.aesDecryptBlock(
          decrypted,
          0,
          aes.aesBlocksFromBytes(cipherText),
          0,
          aes.aesExpandKeyForDecrypting(SecretKeyData(key)),
        );
        expect(
          hexFromBytes(Uint8List.view(decrypted.buffer, 0, cipherText.length)),
          hexFromBytes(clearText),
        );
      });
    });

    group('256-bit key:', () {
      // From appendix of the AES specification:
      // https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf
      final clearText = hexToBytes(
        '00112233445566778899aabbccddeeff',
      );
      final key = hexToBytes(
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
      );
      final cipherText = hexToBytes(
        '8ea2b7ca516745bfeafc49904b496089',
      );

      test('encrypt', () {
        final encrypted = Uint32List(cipherText.length);
        aes.aesEncryptBlock(
          encrypted,
          0,
          aes.aesBlocksFromBytes(clearText),
          0,
          aes.aesExpandKeyForEncrypting(SecretKeyData(key)),
        );
        expect(
          hexFromBytes(Uint8List.view(encrypted.buffer, 0, cipherText.length)),
          hexFromBytes(cipherText),
        );
      });
      test('decrypt', () {
        final decrypted = Uint32List(cipherText.length);
        aes.aesDecryptBlock(
          decrypted,
          0,
          aes.aesBlocksFromBytes(cipherText),
          0,
          aes.aesExpandKeyForDecrypting(SecretKeyData(key)),
        );
        expect(
          hexFromBytes(Uint8List.view(decrypted.buffer, 0, cipherText.length)),
          hexFromBytes(clearText),
        );
      });
    });
  });
}

void _expectHex(int a, int b) {
  expect(a.toRadixString(16), b.toRadixString(16));
}

int _mul(int a, int b) {
  var result = 0;
  for (var i = 1; i < 256; i *= 2) {
    if (i & b != 0) {
      result ^= a;
    }
    a *= 2;
    if (256 & a != 0) {
      a ^= (1 << 8 | 1 << 4 | 1 << 3 | 1 << 1 | 1 << 0);
    }
  }
  return result;
}
