// Copyright 2019 Gohilla Ltd (https://gohilla.com).
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

import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/utils.dart';
import 'package:test/test.dart';

void main() {
  group('blake2s:', () {
    test('name', () {
      expect(blake2s.name, 'blake2s');
    });

    test('hash length', () {
      expect(blake2s.hashLengthInBytes, 32);
    });

    test('block length', () {
      expect(blake2s.blockLength, 32);
    });

    test('test vector from RFC 7693', () async {
      // The following vector is from RFC 7693:
      // https://tools.ietf.org/html/rfc7693
      final expectedBytes = hexToBytes('''
50 8C 5E 8C 32 7C 14 E2 E1 A7 2B A3 4E EB 45 2F
37 45 8B 20 9E D6 3A 29 4D 99 9B 4C 86 67 59 82
''');

      final hash = await blake2s.hash(utf8.encode('abc'));
      expect(
        hexFromBytes(hash.bytes),
        hexFromBytes(expectedBytes),
      );
    });
  });
}
