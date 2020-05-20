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

import 'package:cryptography/cryptography.dart';

import '../web_crypto/web_crypto.dart';
import 'aes_impl_cbc.dart';
import 'aes_impl_ctr.dart';
import 'aes_impl_gcm.dart';

/// _AES_ with Cipher Block Chaining mode (AES-CBC).
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
const Cipher aesCbc = webAesCbc ?? dartAesCbc;

/// _AES-CTR_ cipher.
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
const Cipher aesCtr = webAesCtr ?? dartAesCtr;

/// _AES-GCM_ (Galois/Counter Mode) cipher.
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
const Cipher aesGcm = webAesGcm ?? dartAesGcm;
