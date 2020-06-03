// Copyright 2019-2020 Gohilla Ltd.
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

import 'package:cryptography/src/cryptography/algorithms/argon2.dart';
import 'package:cryptography/utils.dart';
import 'package:test/test.dart';

void main() {
  group('argon2', () {
    test('test vector from RFC 7693', () async {
      final argon2 = Argon2id(
        parallelism: 3,
        memorySize: 32 * 1024,
        iterations: 3,
        hashLength: 32,
      );

      final actual = argon2.deriveKeySync(
        List<int>.filled(32, 0x1),
        salt: List<int>.filled(16, 0x2),
        key: List<int>.filled(8, 0x3),
        ad: List<int>.filled(12, 0x4),
      );

      final expected = hexToBytes(
        '51 2b 39 1b 6f 11 62 97'
        '53 71 d3 09 19 73 42 94'
        'f8 68 e3 be 39 84 f3 c1'
        'a1 3a 4d b9 fa be 4a cb',
      );

      expect(
        hexFromBytes(actual),
        hexFromBytes(expected),
      );
    });
  }, skip: 'Argon2 is not implemented yet');
}
