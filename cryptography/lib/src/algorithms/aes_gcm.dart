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

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/src/utils.dart';
import 'package:meta/meta.dart';

import '../web_crypto/web_crypto.dart' as web_crypto;
import 'aes_impl.dart';

/// _AES-GCM_ (Galois/Counter Mode) cipher.
///
/// In browsers, asynchronous methods attempt to use Web Cryptography API.
/// Otherwise pure Dart implementation is used.
///
/// ## Things to know
/// * `secretKey` can be any value with 128, 192, or 256 bits. By default,
///   [Cipher.newSecretKey] returns 256 bit keys.
/// * `nonce` can be 12 bytes or longer.
/// * AES-GCM is authenticated so you don't need a separate MAC algorithm.
/// * In browsers, the implementation takes advantage of _Web Cryptography API_.
///
/// ## Example
/// ```dart
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   final message = utf8.encode('Encrypted message');
///
///   const cipher = aesGcm;
///   final secretKey = cipher.newSecretKeySync();
///   final nonce = cipher.newNonce();
///
///   // Encrypt
///   final encrypted = await cipher.encrypt(
///     input,
///     secretKey: secretKey,
///     nonce: nonce,
///   );
///
///   // Decrypt
///   final decrypted = await cipher.encrypt(
///     encryptedBytes,
///     secretKey: secretKey,
///     nonce: nonce,
///   );
/// }
/// ```
const Cipher aesGcm = AesGcm();

int _uint32ChangeEndian(int v) {
  // We mask with 0xFFFFFFFF to ensure the compiler recognizes the value will
  // be small enough to be a 'mint'.
  return (0xFFFFFFFF & ((0xFF & v) << 24)) |
      (0xFFFFFF & ((0xFF & (v >> 8)) << 16)) |
      (0xFFFF & ((0xFF & (v >> 16)) << 8)) |
      (0xFF & (v >> 24));
}

/// _AES-GCM_ implementation for subclassing.
/// For documentation, see [aesGcm].
class AesGcm extends AesCipher {
  static final _r = () {
    final result = Uint32List(4);
    Uint8List.view(result.buffer)..[0] = 0xe1;
    return result;
  }();

  const AesGcm();

  @override
  bool get isAuthenticated => true;

  @override
  String get name => 'aesGcm';

  @override
  int get nonceLength => 12;

  @override
  bool get supportsAad => true;

  @override
  Future<Uint8List> decrypt(
    List<int> cipherText, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) async {
    if (web_crypto.isWebCryptoSupported) {
      // Try performing this operation with Web Cryptography
      try {
        return web_crypto.aesGcmDecrypt(
          cipherText,
          secretKey: secretKey,
          nonce: nonce,
          aad: aad,
        );
      } catch (e) {
        if (webCryptoThrows) {
          rethrow;
        }
      }
    }
    final secretKeyBytes = await secretKey.extract();
    return _decrypt(
      cipherText,
      secretKey: secretKey,
      secretKeyBytes: secretKeyBytes,
      nonce: nonce,
      aad: aad,
      keyStreamIndex: keyStreamIndex,
    );
  }

  @override
  Uint8List decryptSync(
    List<int> cipherText, {
    SecretKey secretKey,
    Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) {
    final secretKeyBytes = secretKey.extractSync();
    return _decrypt(
      cipherText,
      secretKey: secretKey,
      secretKeyBytes: secretKeyBytes,
      nonce: nonce,
      aad: aad,
      keyStreamIndex: keyStreamIndex,
    );
  }

  @override
  Future<Uint8List> encrypt(
    List<int> cipherText, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) async {
    if (web_crypto.isWebCryptoSupported) {
      // Try performing this operation with Web Cryptography
      try {
        return web_crypto.aesGcmEncrypt(
          cipherText,
          secretKey: secretKey,
          nonce: nonce,
          aad: aad,
        );
      } catch (e) {
        if (webCryptoThrows) {
          rethrow;
        }
      }
    }
    final secretKeyBytes = await secretKey.extract();
    return _encrypt(
      cipherText,
      secretKey: secretKey,
      secretKeyBytes: secretKeyBytes,
      nonce: nonce,
      aad: aad,
      keyStreamIndex: keyStreamIndex,
    );
  }

  @override
  Uint8List encryptSync(
    List<int> plainText, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) {
    final secretKeyBytes = secretKey.extractSync();
    return _encrypt(
      plainText,
      secretKey: secretKey,
      secretKeyBytes: secretKeyBytes,
      nonce: nonce,
      aad: aad,
      keyStreamIndex: keyStreamIndex,
    );
  }

  @override
  List<int> getDataInCipherText(List<int> cipherText) {
    return cipherText.sublist(
      0,
      cipherText.length - 16,
    );
  }

  @override
  Mac getMacInCipherText(List<int> cipherText) {
    return Mac(cipherText.sublist(
      cipherText.length - 16,
      cipherText.length,
    ));
  }

  @override
  Future<SecretKey> newSecretKey({int length}) {
    length ??= secretKeyLength;
    if (web_crypto.isWebCryptoSupported) {
      return web_crypto.aesNewSecretKey(name: 'AES-GCM', bits: 8 * length);
    }
    return super.newSecretKey(length: length);
  }

  Uint8List _decrypt(
    List<int> cipherText, {
    @required SecretKey secretKey,
    @required List<int> secretKeyBytes,
    @required Nonce nonce,
    @required List<int> aad,
    @required int keyStreamIndex,
  }) {
    final expandedKey = aesExpandKeyForEncrypting(secretKey, secretKeyBytes);

    final h = Uint8List(16);
    final hAsUint32List = Uint32List.view(h.buffer);
    aesEncryptBlock(
      hAsUint32List,
      0,
      hAsUint32List,
      0,
      expandedKey,
    );

    // Construct nonce
    var nonceAsUint32List = Uint32List(4);
    var nonceAsUint8List = Uint8List.view(nonceAsUint32List.buffer);
    final nonceLength = nonce.bytes.length;
    if (nonceLength == 12) {
      nonceAsUint8List.setAll(0, nonce.bytes);
      nonceAsUint8List[nonceAsUint8List.length - 1] = 1;
    } else {
      final tmp = Uint8List((nonceLength + 15) ~/ 16 * 16 + 16);
      tmp.setAll(0, nonce.bytes);
      final tmpByteData = ByteData.view(
        tmp.buffer,
        tmp.lengthInBytes - 4,
        4,
      );
      tmpByteData.setUint32(0, 8 * nonceLength, Endian.big);
      nonceAsUint8List = _ghash(h, tmp);
      nonceAsUint32List = Uint32List.view(nonceAsUint8List.buffer);
    }

    // Calculate MAC
    final mac = _mac(
      cipherText.sublist(0, cipherText.length - 16),
      aad: aad,
      expandedKey: expandedKey,
      h: h,
      precounterBlock: nonceAsUint32List,
    );
    final last16Bytes = cipherText.sublist(
      cipherText.length - 16,
      cipherText.length,
    );
    final isOk = constantTimeBytesEquality.equals(
      last16Bytes,
      mac,
    );
    if (!isOk) {
      throw MacValidationException();
    }

    // Increment nonce
    bytesAsBigEndianAddInt(nonceAsUint8List, 1);

    // Allocate output bytes
    final outputAsUint32List = Uint32List(
      (cipherText.length - 16 + 15) ~/ 16 * 4,
    );

    // For each block
    for (var i = 0; i < outputAsUint32List.length; i += 4) {
      // Encrypt nonce
      aesEncryptBlock(
        outputAsUint32List,
        i,
        nonceAsUint32List,
        0,
        expandedKey,
      );

      // Increment nonce.
      bytesAsBigEndianAddInt(nonceAsUint8List, 1);
    }
    final outputAsUint8List = Uint8List.view(
      outputAsUint32List.buffer,
      0,
      cipherText.length - 16,
    );
    for (var i = 0; i < outputAsUint8List.length; i++) {
      outputAsUint8List[i] ^= cipherText[i];
    }
    return outputAsUint8List;
  }

  Uint8List _encrypt(
    List<int> plainText, {
    @required SecretKey secretKey,
    @required List<int> secretKeyBytes,
    @required Nonce nonce,
    @required List<int> aad,
    @required int keyStreamIndex,
  }) {
    final expandedKey = aesExpandKeyForEncrypting(secretKey, secretKeyBytes);

    final h = Uint8List(16);
    final hAsUint32List = Uint32List.view(h.buffer);
    aesEncryptBlock(
      hAsUint32List,
      0,
      hAsUint32List,
      0,
      expandedKey,
    );

    // Construct nonce
    var nonceAsUint32List = Uint32List(4);
    var nonceAsUint8List = Uint8List.view(nonceAsUint32List.buffer);
    final nonceLength = nonce.bytes.length;
    if (nonceLength == 12) {
      nonceAsUint8List.setAll(0, nonce.bytes);
      nonceAsUint8List[nonceAsUint8List.length - 1] = 1;
    } else {
      final tmp = Uint8List((nonceLength + 15) ~/ 16 * 16 + 16);
      tmp.setAll(0, nonce.bytes);
      final tmpByteData = ByteData.view(
        tmp.buffer,
        tmp.lengthInBytes - 4,
        4,
      );
      tmpByteData.setUint32(0, 8 * nonceLength, Endian.big);
      nonceAsUint8List = _ghash(h, tmp);
      nonceAsUint32List = Uint32List.view(nonceAsUint8List.buffer);
    }

    // Store precounter
    final precounterBlock = Uint32List(4)..setAll(0, nonceAsUint32List);

    // Increment nonce
    bytesAsBigEndianAddInt(nonceAsUint8List, 1);

    // Allocate output bytes
    final m = keyStreamIndex % 16;
    final outputAsUint32List = Uint32List(
      (m + plainText.length + 15) ~/ 16 * 4 + 4,
    );

    // For each block
    for (var i = 0; i < outputAsUint32List.length; i += 4) {
      // Encrypt nonce
      aesEncryptBlock(
        outputAsUint32List,
        i,
        nonceAsUint32List,
        0,
        expandedKey,
      );

      // Increment nonce.
      bytesAsBigEndianAddInt(nonceAsUint8List, 1);
    }

    // Return output of the correct length
    final result = Uint8List.view(
      outputAsUint32List.buffer,
      outputAsUint32List.offsetInBytes + keyStreamIndex % 16,
      plainText.length + 16,
    );

    // XOR
    final cipherText = Uint8List.view(result.buffer, m, plainText.length);
    for (var i = 0; i < plainText.length; i++) {
      cipherText[i] ^= plainText[i];
    }

    // Calculate MAC
    final mac = _mac(
      cipherText,
      aad: aad,
      expandedKey: expandedKey,
      h: h,
      precounterBlock: precounterBlock,
    );

    result.setAll(plainText.length, mac);
    return result;
  }

  Uint8List _mac(
    List<int> cipherText, {
    @required Uint32List precounterBlock,
    @required List<int> h,
    @required List<int> expandedKey,
    @required List<int> aad,
  }) {
    // Calculate MAC
    // TODO: Don't allocate a new array
    final macArgument = _macDataFrom(aad, cipherText);
    final macAsUint8List = _ghash(h, macArgument);
    final macAsUint32List = Uint32List.view(
      macAsUint8List.buffer,
      0,
      4,
    );

    // mac ^= encrypted_precounter
    final macKeyStreamAsUint32List = Uint32List(4);
    aesEncryptBlock(
      macKeyStreamAsUint32List,
      0,
      precounterBlock,
      0,
      expandedKey,
    );
    for (var i = 0; i < 4; i++) {
      macAsUint32List[i] ^= macKeyStreamAsUint32List[i];
    }
    return macAsUint8List;
  }

  static Uint8List _ghash(Uint8List h, Uint8List x) {
    final xAsUint32List = Uint32List.view(
      x.buffer,
      x.offsetInBytes,
    );
    final hAsUint32List = Uint32List.view(h.buffer);
    final result = Uint8List(16);
    final resultAsUint32List = Uint32List.view(
      result.buffer,
      result.offsetInBytes,
    );
    final z = Uint32List(4);
    for (var i = 0; i < x.length; i += 16) {
      // result ^= x_i
      resultAsUint32List[0] ^= xAsUint32List[i ~/ 4];
      resultAsUint32List[1] ^= xAsUint32List[i ~/ 4 + 1];
      resultAsUint32List[2] ^= xAsUint32List[i ~/ 4 + 2];
      resultAsUint32List[3] ^= xAsUint32List[i ~/ 4 + 3];

      // result *= h
      _mulBlocks(
        resultAsUint32List,
        hAsUint32List,
        z,
      );
    }
    return result;
  }

  static Uint8List _macDataFrom(List<int> aad, Uint8List cipherText) {
    aad ??= const <int>[];
    var aadPaddedLength = (aad.length + 15) ~/ 16 * 16;
    var cipherTextPaddedLength = (cipherText.length + 15) ~/ 16 * 16;
    final macData = Uint8List(
      aadPaddedLength + cipherTextPaddedLength + 16,
    );
    macData.setAll(0, aad);
    macData.setAll(aadPaddedLength, cipherText);
    final macDataByteData = ByteData.view(
      macData.buffer,
      macData.length - 16,
      16,
    );
    macDataByteData.setUint32(4, 8 * aad.length, Endian.big);
    macDataByteData.setUint32(12, 8 * cipherText.length, Endian.big);
    return macData;
  }

  static void _mulBlocks(Uint32List x, Uint32List y, Uint32List z) {
    for (var i = 0; i < 4; i++) {
      z[i] = 0;
    }
    final v = x;
    for (var i = 0; i < 128; i++) {
      if (_uint32ChangeEndian(y[i ~/ 32]) & (1 << (31 - i % 32)) != 0) {
        _xorBlocks(z, 0, v, 0);
      }
      var carry = 0;
      for (var i = 0; i < 4; i++) {
        final byte = _uint32ChangeEndian(v[i]);
        v[i] = _uint32ChangeEndian(carry | (byte >> 1));
        carry = 0xFFFFFFFF & ((0x1 & byte) << 31);
      }
      if (carry != 0) {
        _xorBlocks(v, 0, _r, 0);
      }
    }
    for (var i = 0; i < 4; i++) {
      x[i] = z[i];
    }
  }

  static void _xorBlocks(Uint32List a, int ai, Uint32List b, int bi) {
    a[ai] ^= b[bi];
    a[ai + 1] ^= b[bi + 1];
    a[ai + 2] ^= b[bi + 2];
    a[ai + 3] ^= b[bi + 3];
  }
}
