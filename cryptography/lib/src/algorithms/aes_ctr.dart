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

/// _AES-CTR_ cipher ("counter mode").
///
/// In browsers, asynchronous methods attempt to use Web Cryptography API.
/// Otherwise pure Dart implementation is used.
///
/// ## Things to know
/// * `secretKey` can be any value with 128, 192, or 256 bits. By default, the
///   [Cipher.newSecretKey] returns 256 bit keys.
/// * `nonce` must be 8 - 16 bytes.
/// * AES-CTR is NOT authenticated so you should use a separate MAC algorithm
///   (see example).
/// * In browsers, the implementation takes advantage of _Web Cryptography API_.
///
/// AES-CTR takes a maximum 16-byte [Nonce].
///
/// ## Example
/// ```dart
/// import 'package:cryptography/cryptography.dart';
///
/// void main() {
///   final message = utf8.encode('Encrypted message');
///
///   // AES-CTR is NOT authenticated,
///   // so we should use some MAC algorithm such as HMAC-SHA256.
///   const cipher = CipherWithAppendedMac(aesCtr, Hmac(sha256));
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
const Cipher aesCtr = _AesCtr();

class _AesCtr extends AesCipher {
  const _AesCtr();

  @override
  String get name => 'aesCtr';

  @override
  int get nonceLength => 16;

  @override
  int get nonceLengthMax => 16;

  @override
  int get nonceLengthMin => 12;

  @override
  Future<Uint8List> decrypt(List<int> cipherText,
      {SecretKey secretKey,
      Nonce nonce,
      List<int> aad,
      int keyStreamIndex = 0}) {
    if (web_crypto.isWebCryptoSupported) {
      // Try performing this operation with Web Cryptography
      try {
        return web_crypto.aesCtrDecrypt(
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
    // Encryption function can be used for decrypting too.
    return encryptSync(
      input,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
      keyStreamIndex: keyStreamIndex,
    );
  }

  @override
  Future<Uint8List> encrypt(List<int> plainText,
      {SecretKey secretKey,
      Nonce nonce,
      List<int> aad,
      int keyStreamIndex = 0}) {
    if (web_crypto.isWebCryptoSupported) {
      try {
        return web_crypto.aesCtrDecrypt(
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
    List<int> plainText, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) {
    // Check arguments
    final secretKeyBytes = secretKey.extractSync();
    checkCipherParameters(
      this,
      secretKeyLength: secretKeyBytes.length,
      nonce: nonce,
      aad: aad != null,
      keyStreamIndex: keyStreamIndex,
      // TODO: Support any keyStreamIndex
      keyStreamFactor: 1,
    );

    // Create 16 byte nonce from a possibly shorter nonce.
    final nonceAsUint8List = Uint8List(16);
    nonceAsUint8List.setAll(0, nonce.bytes);
    final nonceAsUint32List = Uint32List.view(nonceAsUint8List.buffer);

    // Append key stream index
    if (keyStreamIndex != 0) {
      bytesAsBigEndianAddInt(nonceAsUint8List, keyStreamIndex ~/ 16);
    }

    // Allocate output bytes
    final outputAsUint32List = Uint32List(
      (keyStreamIndex % 16 + plainText.length + 15) ~/ 16 * 4,
    );

    // Expand AES key
    final preparedKey = aesExpandKeyForEncrypting(
      secretKey,
      secretKeyBytes,
    );

    // For each block
    for (var i = 0; i < outputAsUint32List.length; i += 4) {
      // Encrypt nonce with AES
      aesEncryptBlock(
        outputAsUint32List,
        i,
        nonceAsUint32List,
        0,
        preparedKey,
      );

      // Increment nonce.
      bytesAsBigEndianAddInt(nonceAsUint8List, 1);
    }

    // Construct the returned view
    final outputAsUint8List = Uint8List.view(
      outputAsUint32List.buffer,
      keyStreamIndex % 16,
      plainText.length,
    );

    // output ^= plainText
    for (var i = 0; i < plainText.length; i++) {
      outputAsUint8List[i] ^= plainText[i];
    }

    return outputAsUint8List;
  }

  @override
  Future<SecretKey> newSecretKey({int length}) {
    length ??= secretKeyLength;
    if (web_crypto.isWebCryptoSupported) {
      return web_crypto.aesNewSecretKey(name: 'AES-CTR', bits: 8 * length);
    }
    return super.newSecretKey(length: length);
  }
}
