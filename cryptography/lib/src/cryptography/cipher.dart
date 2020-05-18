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
import 'package:meta/meta.dart';

/// An authenticated or unauthenticated cipher.
///
/// In most situations, you should use authenticated ciphers. You can make
/// a non-authenticated cipher authenticated by using the subclass
/// [CipherWithAppendedMac].
///
/// ## Algorithms
///   * [aesCbc] (AES-CBC)
///   * [aesCtr] (AES-CTR)
///   * [aesGcm] (AES-GCM, authenticated)
///   * [chacha20]
///   * [chacha20Poly1305Aead] (authenticated)
///   * [xchacha20]
///   * [xchacha20Poly1305Aead] (authenticated)
///
/// ## Example
/// An example of using [chacha20Poly1305Aead]:
/// ```dart
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   // Generate a random 256-bit secret key
///   final secretKey = SecretKey.randomBytes(32);
///
///   // Generate a random 96-bit nonce.
///   final nonce = Nonce.randomBytes(12);
///
///   // Encrypt
///   final plainText = <int>[1, 2, 3];
///   final encrypted = await chacha20Poly1305Aead.encrypt(
///     plainText,
///     secretKey: secretKey,
///     nonce: nonce,
///   );
///
///   print('Bytes: ${chacha20Poly1305Aead.getDataInCipherText(encrypted)}');
///   print('MAC: ${chacha20Poly1305Aead.getMacInCipherText(encrypted)}');
///
///   // Decrypt.
///   //
///   // If the message authentication code is incorrect,
///   // the method will return null.
///   //
///   final decrypted = await algorithm.decrypt(
///     cipherText,
///     secretKey: secretKey,
///     nonce: nonce,
///   );
/// }
/// ```
abstract class Cipher {
  const Cipher();

  /// Whether the cipher does authentication.
  ///
  /// Default is false.
  bool get isAuthenticated => false;

  /// A descriptive algorithm name for debugging purposes.
  ///
  /// Examples:
  ///   * "chacha20"
  ///   * "chacha20-Hmac(sha256)"
  String get name;

  /// The recommended length of nonce in bytes.
  int get nonceLength => null;

  /// Minimum length of nonce in bytes.
  int get nonceLengthMin => null;

  /// Maximum length of nonce in bytes.
  int get nonceLengthMax => null;

  /// The recommended length of secret key in bytes.
  int get secretKeyLength;

  /// All valid secret key lengths (in bytes).
  ///
  /// For example, _AES_ has three valid lengths: 16, 24, and 32 bytes.
  Set<int> get secretKeyValidLengths;

  /// Whether the algorithm supports Associated Authenticated Data (AAD).
  ///
  /// Default is false.
  bool get supportsAad => false;

  /// Decrypts a message.
  ///
  /// You must give a non-null [secretKey] that has a valid length
  /// ([secretKeyValidLengths]).
  ///
  /// Some algorithms require you to define a [nonce] (also known as
  /// "initialization vector", "IV", or "salt"), which is some non-secret
  /// unique sequence of bytes.
  ///
  /// Parameter [aad] can be used to pass Associated Authenticated Data (AAD).
  /// If you give a non-null value and [supportsAad] is `false`, this method
  /// will throw [UnsupportedError].
  ///
  /// Parameter [keyStreamIndex] can be used to define key stream index.
  /// If you give a non-zero value, non-stream algorithms will throw
  /// [UnsupportedError].
  ///
  /// Authenticated ciphers (such as [CipherWithAppendedMac]) should throw
  /// [MacValidationException] if the message has an incorrect MAC.
  Future<Uint8List> decrypt(
    List<int> cipherText, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) async {
    return decryptSync(
      cipherText,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
      keyStreamIndex: keyStreamIndex,
    );
  }

  /// Decrypts a message. Unlike [decrypt], this method is synchronous.
  /// If the operation can not be performed synchronously, the method throws
  /// [UnsupportedError].
  ///
  /// For more information, see [decrypt].
  Uint8List decryptSync(
    List<int> cipherText, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  });

  /// Decrypts a message. The output is written into the buffer.
  /// Returns the number of written bytes.
  ///
  /// For more information, see [decrypt].
  Future<int> decryptToBuffer(
    List<int> cipherText, {
    @required List<int> buffer,
    int bufferStart = 0,
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) async {
    ArgumentError.checkNotNull(buffer, 'buffer');
    ArgumentError.checkNotNull(bufferStart, 'bufferStart');
    final tmp = await decrypt(
      cipherText,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
      keyStreamIndex: keyStreamIndex,
    );
    buffer.setAll(bufferStart, tmp);
    return tmp.length;
  }

  /// Encrypts a message.
  ///
  /// You must give a non-null [secretKey] that has a valid length
  /// ([secretKeyValidLengths]).
  ///
  /// Some algorithms require you to define a [nonce] (also known as
  /// "initialization vector", "IV", or "salt"), which is some non-secret
  /// unique sequence of bytes.
  ///
  /// Parameter [aad] can be used to pass Associated Authenticated Data (AAD).
  /// If you give a non-null value and [supportsAad] is `false`, this method
  /// will throw [UnsupportedError].
  ///
  /// Parameter [keyStreamIndex] can be used to define key stream index.
  /// If you give a non-zero value, non-stream algorithms will throw
  /// [UnsupportedError].
  Future<Uint8List> encrypt(
    List<int> plainText, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) async {
    return encryptSync(
      plainText,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
      keyStreamIndex: keyStreamIndex,
    );
  }

  /// Encrypts a message. Unlike [encrypt], this method is synchronous.
  /// If the operation can not be performed synchronously, the method throws
  /// [UnsupportedError].
  ///
  /// For more information, see [encrypt].
  Uint8List encryptSync(
    List<int> plainText, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  });

  /// Encrypts a message. The output is written into the buffer.
  /// Returns the number of written bytes.
  ///
  /// For more information, see [encrypt].
  Future<int> encryptToBuffer(
    List<int> plainText, {
    @required List<int> buffer,
    int bufferStart = 0,
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) async {
    ArgumentError.checkNotNull(buffer, 'buffer');
    ArgumentError.checkNotNull(bufferStart, 'bufferStart');
    final tmp = await encrypt(
      plainText,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
      keyStreamIndex: keyStreamIndex,
    );
    buffer.setAll(bufferStart, tmp);
    return tmp.length;
  }

  /// If cipherTexts of this cipher contain MACs, returns the non-MAC bytes.
  /// Otherwise returns null.
  ///
  /// Examples of algorithms that support this method:
  ///   * [CipherWithAppendedMac]
  ///   * [chacha20Poly1305Aead]
  List<int> getDataInCipherText(List<int> cipherText) {
    assert(!isAuthenticated);
    return cipherText;
  }

  /// If cipherTexts of this cipher contain MACs, returns the MAC. Otherwise
  /// returns null.
  ///
  /// Examples of algorithms that support this method:
  ///   * [CipherWithAppendedMac]
  ///   * [chacha20Poly1305Aead]
  Mac getMacInCipherText(List<int> cipherText) {
    return null;
  }

  /// Generates a random nonce of length [nonceLength].
  Nonce newNonce() {
    final nonceLength = this.nonceLength;
    if (nonceLength == null) {
      return null;
    }
    return Nonce.randomBytes(nonceLength);
  }

  /// Generates a random secret key of the specific length (in bytes). By
  /// default, uses [secretKeyLength].
  Future<SecretKey> newSecretKey({int length}) async {
    return Future<SecretKey>(() => newSecretKeySync(length: length));
  }

  /// Generates a random secret key of the specific length (in bytes). By
  /// default, uses [secretKeyLength].
  SecretKey newSecretKeySync({int length}) {
    length ??= secretKeyLength;
    if (secretKeyValidLengths != null &&
        !secretKeyValidLengths.contains(length)) {
      throw ArgumentError.value(
        length,
        'length',
        'Should be one of: ${secretKeyValidLengths.join(', ')}',
      );
    }
    return SecretKey.randomBytes(length);
  }

  @override
  String toString() => name;
}
