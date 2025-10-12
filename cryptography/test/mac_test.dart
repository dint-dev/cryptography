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
import 'package:test/test.dart';

void main() {
  group('Mac:', () {
    test('"==" / hashCode', () {
      const value = Mac([3, 1, 4]);
      const clone = Mac([3, 1, 4]);
      const other0 = Mac([3, 1, 999]);
      const other1 = Mac([3, 1, 4, 999]);
      const other2 = Mac([3, 1]);

      expect(value, clone);
      expect(value, isNot(other0));
      expect(value, isNot(other1));
      expect(value, isNot(other2));

      expect(value.hashCode, clone.hashCode);
      expect(value.hashCode, isNot(other0.hashCode));
      expect(value.hashCode, isNot(other1.hashCode));
      expect(value.hashCode, isNot(other2.hashCode));
    });

    test('toString() when non-empty', () {
      const value = Mac([3, 1, 4]);
      expect(value.toString(), 'Mac([3,1,4])');
    });

    test('toString() when empty', () {
      const value = Mac.empty;
      expect(value.bytes, isEmpty);
      expect(value.toString(), 'Mac.empty');
    });
  });
}
