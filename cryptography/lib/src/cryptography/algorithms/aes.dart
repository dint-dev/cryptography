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

/// _AES-CBC_ cipher.
///
/// The secret key can be any value with 128, 192, or 256 bits. By default, the
/// key generator returns 256 bit keys.
///
/// An example:
/// ```dart
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   final cipher = aesCbc;
///
///   final input = <int>[1,2,3];
///   final secretKey = cipher.newSecretKeySync();
///   final nonce = cipher.newNonce();
///
///   // Encrypt
///   final encryptedBytes = cipher.encrypt(
///     input,
///     secretKey: secretKey,
///     nonce: nonce,
///   );
///
///   // Decrypt
///   final decryptedBytes = cipher.encrypt(
///     encryptedBytes,
///     secretKey: secretKey,
///     nonce: nonce,
///   );
/// }
/// ```
const Cipher aesCbc = webAesCbc ?? dart.aesCbc;

/// _AES-CTR_ cipher with a 96-bit nonce and a 32-bit counter.
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
///   final cipher = aesCtr;
///
///   final input = <int>[1,2,3];
///   final secretKey = cipher.newSecretKeySync();
///   final nonce = cipher.newNonce();
///
///   // Encrypt
///   final encryptedBytes = cipher.encrypt(
///     input,
///     secretKey: secretKey,
///     nonce: nonce,
///   );
///
///   // Decrypt
///   final decryptedBytes = cipher.encrypt(
///     encryptedBytes,
///     secretKey: secretKey,
///     nonce: nonce,
///   );
/// }
/// ```
const Cipher aesCtr = webAesCtr ?? dart.aesCtr;

/// _AES-GCM_ (Galois/Counter Mode) cipher.
/// Currently supported __only in the browser.__
///
/// The secret key can be any value with 128, 192, or 256 bits. By default, the
/// key generator returns 256 bit keys.
///
/// An example:
/// ```dart
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   final cipher = aesGcm;
///
///   final input = <int>[1,2,3];
///   final secretKey = cipher.newSecretKeySync();
///   final nonce = cipher.newNonce();
///
///   // Encrypt
///   final encryptedBytes = await cipher.encrypt(
///     input,
///     secretKey: secretKey,
///     nonce: nonce,
///   );
///
///   // Decrypt
///   final decryptedBytes = await cipher.encrypt(
///     encryptedBytes,
///     secretKey: secretKey,
///     nonce: nonce,
///   );
/// }
/// ```
const Cipher aesGcm = webAesGcm;
