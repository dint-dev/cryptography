// Copyright 2023 Gohilla.
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

/// Test utilities for cryptographic algorithms.
///
/// Use [testCryptography] to test all algorithms.
///
/// See also:
///   * [testCipher]
///   * [testHashAlgorithm]
///   * [testKeyExchangeAlgorithm]
///   * [testSignatureAlgorithm]
///
/// ## Example
/// ```dart
/// import 'package:cryptography_test/cryptography_test.dart';
///
/// void main() {
///   Cryptography.instance = MyCryptography();
///   testCryptography();
/// }
/// ```
library cryptography_plus_test;

import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:cryptography_test/algorithms/argon2.dart';
import 'package:test/scaffolding.dart';

import 'algorithms/aes_cbc.dart';
import 'algorithms/aes_ctr.dart';
import 'algorithms/aes_gcm.dart';
import 'algorithms/blake2b.dart';
import 'algorithms/blake2s.dart';
import 'algorithms/chacha20.dart';
import 'algorithms/ecdh.dart';
import 'algorithms/ecdsa.dart';
import 'algorithms/ed25519.dart';
import 'algorithms/hkdf.dart';
import 'algorithms/hmac.dart';
import 'algorithms/pbkdf2.dart';
import 'algorithms/rsa_pss.dart';
import 'algorithms/rsa_ssa_pkcs5v15.dart';
import 'algorithms/sha224.dart';
import 'algorithms/sha256.dart';
import 'algorithms/sha384.dart';
import 'algorithms/sha512.dart';
import 'algorithms/x25519.dart';
import 'algorithms/xchacha20.dart';
import 'cipher.dart';
import 'hash.dart';
import 'key_exchange.dart';
import 'signature.dart';

/// Tests the current or the given [Cryptography].
void testCryptography({Cryptography? cryptography}) {
  if (cryptography != null) {
    group('$cryptography:', () {
      setUpAll(() {
        Cryptography.instance = cryptography;
      });
      testCryptography();
    });
    return;
  }

  // Hash algorithms
  testBlake2s();
  testBlake2b();
  testSha224();
  testSha256();
  testSha384();
  testSha512();

  // Ciphers
  testAesCbc();
  testAesCtr();
  testAesGcm();
  testChacha20();
  testXchacha20();

  // Key exchange algorithms
  testEcdh();
  testX25519();

  // Signature algorithms
  testEcdsa();
  testEd25519();
  testRsaPss();
  testRsaSsaPkcs5v1();

  // Other
  testHmac();
  testHkdf();
  testPbkdf2();
  testArgon2();
}
