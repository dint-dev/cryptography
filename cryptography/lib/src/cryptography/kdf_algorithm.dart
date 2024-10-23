// Copyright 2019-2020 Gohilla.
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

import 'dart:convert';

import 'package:cryptography_plus/cryptography_plus.dart';

/// Abstract superclass for Key Derivation Algorithms (KDFs).
///
/// ## Available algorithms
///   * [Argon2id] (recommended for password hashing)
///   * [Hchacha20]
///   * [Hkdf]
///   * [Pbkdf2]
abstract class KdfAlgorithm {
  const KdfAlgorithm();

  /// Generates a new secret key from a secret key and a nonce.
  ///
  /// The nonce ("salt") should be some random sequence of bytes. Nonce does not
  /// need to be protected. If possible, you should have a different nonce for
  /// each key derivation.
  Future<SecretKey> deriveKey({
    required SecretKey secretKey,
    required List<int> nonce,
  });

  /// Generates a new secret key from a [password] and a [nonce].
  ///
  /// The [nonce] (also called a "salt") should be some random sequence of
  /// bytes. Nonce does not need to be protected.
  ///
  /// If possible, you should have a different nonce for each password. For
  /// example, if you are doing server-side password hashing, this could mean
  /// generating a random 32-byte nonce and storing it in the database along
  /// with the hashed password.
  ///
  /// The default implementation encodes the string using [utf8] and calls
  /// [deriveKey].
  Future<SecretKey> deriveKeyFromPassword({
    required String password,
    required List<int> nonce,
  }) async {
    return deriveKey(
      secretKey: SecretKey(utf8.encode(password)),
      nonce: nonce,
    );
  }
}
