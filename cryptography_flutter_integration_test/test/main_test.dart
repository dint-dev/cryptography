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

import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:cryptography_flutter_plus/cryptography_flutter_plus.dart';
import 'package:flutter_test/flutter_test.dart';

import '_android_crypto_provider.dart';
import '_ciphers.dart';
import '_ecdh.dart';
import '_ecdsa.dart';
import '_ed25519.dart';
import '_flutter_cryptography.dart';
import '_hmac.dart';
import '_pbkdf2.dart.dart';
import '_rsa_pss.dart';
import '_rsa_ssa_pkcs1v15.dart';
import '_x25519.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  runTests();
}

void runTests() {
  // IMPORTANT:
  // We must do this now so test descriptions are correct.
  Cryptography.instance = FlutterCryptography.defaultInstance;

  setUp(() {
    final oldCryptography = Cryptography.instance;
    Cryptography.instance = FlutterCryptography.defaultInstance;
    addTearDown(() {
      Cryptography.instance = oldCryptography;
    });
  });

  testAndroidCryptoProvider();

  testFlutterCryptography();

  testCiphers();

  // Signatures
  testEcdsa();
  testEd25519();
  testRsaPss();
  testRsaSsaPkcs1v15();

  // Key exchange
  testEcdh();
  testX25519();

  // Other
  testHmac();
  testPbkdf2();
}
