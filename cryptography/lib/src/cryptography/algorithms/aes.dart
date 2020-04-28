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

import 'aes_impl.dart' as dart;
import 'web_crypto.dart';

/// _AES_ with Cipher Block Chaining mode (AES-CBC).
///
/// AES-CBC is NOT authenticated so you should use a separate MAC algorithm
/// (see example).
///
/// The secret key can be any value with 128, 192, or 256 bits. By default, the
/// key generator returns 256 bit keys.
///
/// An example:
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
const Cipher aesCbc = webAesCbc ?? dart.aesCbc;

/// _AES-CTR_ cipher with a 96-bit nonce and a 32-bit counter.
///
/// AES-CTR is NOT authenticated so you should use a separate MAC algorithm
/// (see example).
///
/// The secret key can be any value with 128, 192, or 256 bits. By default, the
/// key generator returns 256 bit keys.
///
/// AES-CTR takes a 16-byte initialization vector and allows you to specify how
/// many right-most bits are taken by the counter.
///
/// An example:
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
const Cipher aesCtr = webAesCtr ?? dart.aesCtr;

/// _AES-GCM_ (Galois/Counter Mode) cipher.
/// Currently supported __only in the browser.__
///
/// AES-GCM is authenticated so you don't need a separate MAC algorithm.
///
/// The secret key can be any value with 128, 192, or 256 bits. By default, the
/// key generator returns 256 bit keys.
///
/// An example:
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
const Cipher aesGcm = webAesGcm;
