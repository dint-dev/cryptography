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
import 'package:cryptography_test/algorithms/pbkdf2.dart' as shared;
import 'package:flutter_test/flutter_test.dart';

void testPbkdf2() {
  group('$FlutterCryptography:', () {
    shared.testPbkdf2();
  });

  group('$_BackgroundCryptography:', () {
    // Using setUp() is not enough because we want correct test descriptions.
    final oldCryptography = Cryptography.instance;
    Cryptography.instance = _BackgroundCryptography();

    setUp(() {
      Cryptography.instance = _BackgroundCryptography();
    });
    shared.testPbkdf2();

    Cryptography.instance = oldCryptography;
  });
}

class _BackgroundCryptography extends FlutterCryptography {
  @override
  Pbkdf2 pbkdf2({
    required MacAlgorithm macAlgorithm,
    required int iterations,
    required int bits,
  }) {
    return BackgroundPbkdf2(
      macAlgorithm: macAlgorithm,
      bits: bits,
      iterations: iterations,
    );
  }
}
