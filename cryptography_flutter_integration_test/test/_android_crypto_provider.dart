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

import 'dart:io';

import 'package:cryptography_flutter_plus/android.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';

void testAndroidCryptoProvider() {
  if (!kIsWeb && Platform.isAndroid) {
    test('AndroidCryptoProvider.all', () async {
      final providers = await AndroidCryptoProvider.all();
      expect(providers, hasLength(greaterThan(1)));
    });

    test('AndroidCryptoProvider.add("non-existing")', () async {
      try {
        await AndroidCryptoProvider.add(className: 'nonExistingCryptoProvider');
      } catch (e) {
        expect(e.toString(), contains('java.lang.ClassNotFoundException'));
      }
    });
  }
}
