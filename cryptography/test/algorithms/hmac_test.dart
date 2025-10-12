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
import 'package:cryptography_plus/dart.dart';
import 'package:test/test.dart';

void main() {
  // ---------------------------------------------------------------------------
  //
  // IMPORTANT:
  //
  // We've migrated most of the tests to 'cryptography_test'.
  // This file is only for tests that are specific to the 'cryptography'
  // package.
  //
  // ---------------------------------------------------------------------------
  group('Hmac:', () {
    group('non-browser:', () {
      _main();
    }, testOn: '!browser');

    group('browser:', () {
      _main();
    }, testOn: 'browser');
  });
}

void _main() {
  final prefix = BrowserCryptography.isSupported ? 'Browser' : 'Dart';

  test('Hmac.sha1().toString()', () {
    expect(Hmac.sha1().toString(), '${prefix}Hmac(${prefix}Sha1())');
    expect(DartHmac.sha1().toString(), 'DartHmac(${prefix}Sha1())');
  });

  test('Hmac.sha224().toString()', () {
    // Web Cryptography does not support Sha224
    expect(Hmac(Sha224()).toString(), 'DartHmac(DartSha224())');
    expect(DartHmac.sha224().toString(), 'DartHmac(DartSha224())');
  });

  test('Hmac.sha256().toString()', () {
    expect(Hmac.sha256().toString(), '${prefix}Hmac.sha256()');
    expect(DartHmac.sha256().toString(), 'DartHmac.sha256()');
  });

  test('Hmac.sha384().toString()', () {
    expect(Hmac.sha384().toString(), '${prefix}Hmac(${prefix}Sha384())');
    expect(DartHmac.sha384().toString(), 'DartHmac(${prefix}Sha384())');
  });

  test('Hmac.sha512().toString()', () {
    expect(Hmac.sha512().toString(), '${prefix}Hmac.sha512()');
    expect(DartHmac.sha512().toString(), 'DartHmac.sha512()');
  });

  test('hashAlgorithm', () {
    expect(
      Hmac(Sha224()).hashAlgorithm,
      same(Sha224()),
    );
    expect(
      Hmac(Sha256()).hashAlgorithm,
      same(Sha256()),
    );
  });
}
