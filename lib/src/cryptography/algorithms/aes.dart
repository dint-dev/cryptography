// Copyright 2019 Gohilla Ltd (https://gohilla.com).
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

import 'web_crypto.dart';

/// _AES-CBC_ cipher.
/// Currently supported __only in the browser.__
///
/// An example:
/// ```dart
/// import 'package:cryptography/cryptography.dart';
///
/// void main() async {
///   final input = <int>[1,2,3];
///   final cipher = aesGcm;
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
const Cipher aesCbc = webAesCbc ?? _UnsupportedCipher('aesCbc');

/// _AES-CTR_ cipher.
/// Currently supported __only in the browser.__
///
/// An example:
/// ```dart
/// import 'package:cryptography/cryptography.dart';
///
/// void main() {
///   final input = <int>[1,2,3];
///   final cipher = aesGcm;
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
const Cipher aesCtr = webAesCtr ?? _UnsupportedCipher('aesCtr');

/// _AES-GCM_ (Galois/Counter Mode) cipher.
/// Currently supported __only in the browser.__
///
/// An example:
/// ```dart
/// import 'package:cryptography/cryptography.dart';
///
/// void main() async {
///   final input = <int>[1,2,3];
///   final cipher = aesGcm;
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
const Cipher aesGcm = webAesGcm ?? _UnsupportedCipher('aesGcm');

class _UnsupportedCipher extends Cipher {
  @override
  final String name;

  const _UnsupportedCipher(this.name);

  @override
  SecretKeyGenerator get secretKeyGenerator => null;

  @override
  Uint8List decryptSync(
    List<int> input, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    int offset = 0,
  }) {
    throw UnsupportedError('Only supported in the browser');
  }

  @override
  Uint8List encryptSync(
    List<int> input, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    int offset = 0,
  }) {
    throw UnsupportedError('Only supported in the browser');
  }
}
