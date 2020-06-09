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

/// _AES-CBC_ cipher ("cipher block chaining mode").
///
/// In browsers, asynchronous methods attempt to use Web Cryptography API.
/// Otherwise pure Dart implementation is used.
///
/// ## Things to know
/// * `secretKey` can be any value with 128, 192, or 256 bits. By default, the
///   [Cipher.newSecretKey] returns 256 bit keys.
/// * `nonce` must be 12 - 16 bytes.
/// * AES-CBC is NOT authenticated so you should use a separate MAC algorithm
///   (see example).
/// * In browsers, the implementation takes advantage of _Web Cryptography API_.
///
/// ## Example
/// ```dart
/// import 'dart:convert'
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   final message = utf8.encode('Encrypted message');
///
///   // AES-CBC is NOT authenticated,
///   // so we should use some MAC algorithm such as HMAC-SHA256.
///   const cipher = CipherWithAppendedMac(aesCbc, Hmac(sha256));
///
///   // Choose some secret key and nonce
///   final secretKey = cipher.newSecretKeySync();
///   final nonce = cipher.newNonce();
///
///   // Encrypt
///   final encrypted = cipher.encrypt(
///     message,
///     secretKey: secretKey,
///     nonce: nonce,
///   );
///
///   // Decrypt
///   final decrypted = cipher.encrypt(
///     encrypted,
///     secretKey: secretKey,
///     nonce: nonce,
///   );
/// }
/// ```
const Cipher aesCbc = _AesCbc();

class _AesCbc extends AesCipher {
  const _AesCbc();

  @override
  String get name => 'aesCbc';

  @override
  int get nonceLength => 16;

  @override
  Future<Uint8List> decrypt(
    List<int> cipherText, {
    SecretKey secretKey,
    Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) {
    if (web_crypto.isWebCryptoSupported) {
      // Try performing this operation with Web Cryptography
      try {
        return web_crypto.aesCbcDecrypt(
          cipherText,
          secretKey: secretKey,
          nonce: nonce,
        );
      } catch (e) {
        if (webCryptoThrows) {
          rethrow;
        }
      }
    }
    return super.decrypt(
      cipherText,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
      keyStreamIndex: keyStreamIndex,
    );
  }

  @override
  Uint8List decryptSync(
    List<int> input, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) {
    // Validate parameters
    final secretKeyBytes = secretKey.extractSync();
    checkCipherParameters(
      this,
      secretKeyLength: secretKeyBytes.length,
      nonce: nonce,
      aad: aad != null,
      keyStreamIndex: keyStreamIndex,
    );
    if (input.length % 16 != 0) {
      throw ArgumentError('Invalid length: ${input.length}');
    }

    // Expand key
    final preparedKey = aesExpandKeyForDecrypting(secretKey, secretKeyBytes);

    // Construct output
    final outputAsUint32List = Uint32List(input.length ~/ 16 * 4);
    final outputAsUint8List = Uint8List.view(outputAsUint32List.buffer);
    outputAsUint8List.setAll(0, input);
    assert(outputAsUint8List.length == input.length);

    // Current block
    var e0 = 0;
    var e1 = 0;
    var e2 = 0;
    var e3 = 0;

    for (var i = 0; i < outputAsUint32List.length; i += 4) {
      // Memorize previous encrypted block
      final p0 = e0;
      final p1 = e1;
      final p2 = e2;
      final p3 = e3;

      // Memorize encrypted block
      e0 = outputAsUint32List[i];
      e1 = outputAsUint32List[i + 1];
      e2 = outputAsUint32List[i + 2];
      e3 = outputAsUint32List[i + 3];

      // Block function
      aesDecryptBlock(
        outputAsUint32List,
        i,
        outputAsUint32List,
        i,
        preparedKey,
      );

      if (i == 0) {
        // block ^= nonce
        final nonceBytes = nonce.bytes;
        for (var i = 0; i < nonceBytes.length; i++) {
          outputAsUint8List[i] ^= nonceBytes[i];
        }
      } else {
        // block ^= previous_block
        outputAsUint32List[i] ^= p0;
        outputAsUint32List[i + 1] ^= p1;
        outputAsUint32List[i + 2] ^= p2;
        outputAsUint32List[i + 3] ^= p3;
      }
    }

    // PKCS7 padding
    final paddingLength = outputAsUint8List.last;
    if (paddingLength == 0 || paddingLength > 16) {
      throw StateError(
        'Invalid padding length: $paddingLength, ${outputAsUint8List}',
      );
    }

    // Check that all padding bytes are valid
    for (var i = outputAsUint8List.length - paddingLength;
        i < outputAsUint8List.length;
        i++) {
      if (outputAsUint8List[i] != paddingLength) {
        throw StateError('Missing padding');
      }
    }
    if (paddingLength == 0) {
      return outputAsUint8List;
    }
    return Uint8List.view(
      outputAsUint32List.buffer,
      outputAsUint32List.offsetInBytes,
      outputAsUint32List.lengthInBytes - paddingLength,
    );
  }

  @override
  Future<Uint8List> encrypt(
    List<int> plainText, {
    SecretKey secretKey,
    Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) {
    if (web_crypto.isWebCryptoSupported) {
      // Try performing this operation with Web Cryptography
      try {
        return web_crypto.aesCbcEncrypt(
          plainText,
          secretKey: secretKey,
          nonce: nonce,
        );
      } catch (e) {
        if (webCryptoThrows) {
          rethrow;
        }
      }
    }
    return super.encrypt(
      plainText,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
      keyStreamIndex: keyStreamIndex,
    );
  }

  @override
  Uint8List encryptSync(
    List<int> input, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) {
    // Check parameters
    final secretKeyBytes = secretKey.extractSync();
    checkCipherParameters(
      this,
      secretKeyLength: secretKeyBytes.length,
      nonce: nonce,
      aad: aad != null,
      keyStreamIndex: keyStreamIndex,
    );

    // Expand key
    final expandedKey = aesExpandKeyForEncrypting(
      secretKey,
      secretKeyBytes,
    );

    // Construct Uint32List list for the output
    final paddingLength = 16 - input.length % 16;
    final outputAsUint32List = Uint32List(
      (input.length + paddingLength) ~/ 16 * 4,
    );
    final outputAsUint8List = Uint8List.view(outputAsUint32List.buffer);

    // Fill output with input + PKCS7 padding
    outputAsUint8List.setRange(0, input.length, input);
    outputAsUint8List.fillRange(
      input.length,
      outputAsUint8List.lengthInBytes,
      paddingLength,
    );
    if (Endian.host == Endian.big) {
      final outputByteData = ByteData.view(outputAsUint8List.buffer);
      for (var i = 0; i < outputAsUint8List.length; i += 4) {
        outputAsUint8List[i] = outputByteData.getUint32(i, Endian.big);
      }
    }

    for (var i = 0; i < outputAsUint32List.length; i += 4) {
      if (i == 0) {
        // block ^= nonce
        final nonceBytes = nonce.bytes;
        for (var i = 0; i < nonceBytes.length; i++) {
          outputAsUint8List[i] ^= nonceBytes[i];
        }
      } else {
        // block ^= previous_block
        for (var j = 0; j < 4; j++) {
          outputAsUint32List[i + j] ^= outputAsUint32List[i + j - 4];
        }
      }

      // Block function
      aesEncryptBlock(
        outputAsUint32List,
        i,
        outputAsUint32List,
        i,
        expandedKey,
      );
    }
    return outputAsUint8List;
  }

  @override
  Future<SecretKey> newSecretKey({int length}) {
    length ??= secretKeyLength;
    if (web_crypto.isWebCryptoSupported) {
      return web_crypto.aesNewSecretKey(name: 'AES-CBC', bits: 8 * length);
    }
    return super.newSecretKey(length: length);
  }
}
