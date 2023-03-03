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

import 'package:cryptography/browser.dart';
import 'package:cryptography/cryptography.dart';
import 'package:cryptography_flutter/cryptography_flutter.dart';
import 'package:flutter_test/flutter_test.dart';

import '_ciphers.dart';
import '_key_exchange_algorithms.dart';
import '_signature_algorithms.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  runTests();
}

void runTests() {
  // IMPORTANT:
  // This must NOT be inside setUp(() {...}).
  Cryptography.instance = FlutterCryptography.defaultInstance;

  test('Cryptography.instance.aesGcm()', () {
    expect(Cryptography.instance, same(FlutterCryptography.defaultInstance));
    expect(
      Cryptography.instance.aesGcm(),
      anyOf(
        isA<FlutterAesGcm>(),
        isA<BackgroundAesGcm>(),
      ),
    );
  });

  test('Cryptography.instance.chachaPoly1305Aead()', () {
    expect(Cryptography.instance, same(FlutterCryptography.defaultInstance));
    expect(
      Cryptography.instance.chacha20Poly1305Aead(),
      anyOf(
        isA<FlutterChacha20>(),
        isA<BackgroundChacha>(),
      ),
    );
  });

  group('--:', () {
    testCiphers();
    testSignatureAlgorithms();
    testKeyExchangeAlgorithms();
  });

  test('FlutterCryptography.enable', () {
    FlutterCryptography.enable();
    expect(Cryptography.instance, same(FlutterCryptography.defaultInstance));

    FlutterCryptography.enable();
    expect(Cryptography.instance, same(FlutterCryptography.defaultInstance));

    expect(
      () => Cryptography.instance = BrowserCryptography(),
      throwsStateError,
    );
    expect(Cryptography.instance, same(FlutterCryptography.defaultInstance));
  });
}
