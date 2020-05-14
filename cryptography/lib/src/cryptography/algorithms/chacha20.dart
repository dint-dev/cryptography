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

import 'chacha20_impl.dart';

/// _ChaCha20_ cipher ([RFC 7539](https://tools.ietf.org/html/rfc7539)).
///
/// ## Things to know
///   * `secretKey` must be 32 bytes.
///   * `nonce` must be 12 bytes.
///   * `keyStreamIndex` enables choosing index in the key  stream.
///   * Make sure you don't use the same (key, nonce) combination twice.
///   * Make sure you don't use the cipher without authentication (such as
///     [chacha20Poly1305Aead] or [CipherWithAppendedMac]).
///
/// ## Example
/// ```dart
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   final algorithm = chacha20;
///
///   // Generate a random 256-bit secret key
///   final secretKey = await algorithm.newSecretKey();
///
///   // Generate a random 96-bit nonce.
///   final nonce = algorithm.newNonce();
///
///   // Encrypt
///   final encrypted = await algorithm.encrypt(
///     [1, 2, 3],
///     secretKey: secretKey,
///     nonce: nonce,
///   );
///
///   // Decrypt
///   final decrypted = await algorithm.decrypt(
///     encrypted,
///     secretKey: secretKey,
///     nonce: nonce,
///   );
/// }
/// ```
const Cipher chacha20 = Chacha20();
