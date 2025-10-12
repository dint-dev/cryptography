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
import 'package:cryptography_plus/src/utils.dart';
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
  group('Pbkdf2:', () {
    group('DartCryptography:', () {
      setUp(() {
        Cryptography.instance = DartCryptography.defaultInstance;
      });
      _main();
    });
    group('BrowserCryptography:', () {
      setUp(() {
        Cryptography.instance = BrowserCryptography.defaultInstance;
      });
      _main();
    }, testOn: 'browser');
  });
}

void _main() {
  test('deriveKey(...): Hmac(sha256), 10k iterations in 300ms', () async {
    final macAlgorithm = Hmac.sha256();
    final n = 10 * 1000;
    const maxDuration = Duration(milliseconds: 1000);

    final pbkdf2 = Pbkdf2(
      macAlgorithm: macAlgorithm,
      bits: 128,
      iterations: n,
    );
    printOnFailure('Class is: ${pbkdf2.runtimeType}');
    if (pbkdf2 is DartPbkdf2 && BrowserCryptography.isSupported) {
      return;
    }

    final stopwatch = Stopwatch()..start();
    final result = await pbkdf2.deriveKey(
      secretKey: SecretKey([1, 2, 3]),
      nonce: const [],
    );
    final elapsed = stopwatch.elapsed;
    print('Elapsed: $elapsed');

    expect(elapsed, lessThan(maxDuration));
    expect(
      hexFromBytes(await result.extractBytes()),
      'd1 c9 30 d5 39 aa f7 46 25 8c bf 31 fe 82 05 54',
    );
  });
}
