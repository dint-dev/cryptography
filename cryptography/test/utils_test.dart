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

import 'package:cryptography_plus/helpers.dart';
import 'package:test/test.dart';

void main() {
  test('randomBytes()', () {
    for (var i = 1; i < 100; i++) {
      final s = randomBytes(i);
      expect(s.length, i);
      expect(s.toSet(), hasLength(greaterThan(s.length ~/ 8)));
    }
  });

  test('randomBytesAsHexString()', () {
    for (var i = 1; i < 100; i++) {
      final s = randomBytesAsHexString(i);
      expect(s.length, 2 * i);
      if (i >= 32) {
        expect(s.codeUnits.toSet(), hasLength(greaterThan(8)));
      }
    }
  });
}
