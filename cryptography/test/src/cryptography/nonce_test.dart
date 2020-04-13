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

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';

void main() {
  group('Nonce:', () {
    test('Nonce.randomBytes()', () {
      final a = Nonce.randomBytes(32);
      final b = Nonce.randomBytes(32);
      expect(a, isNot(b));
      expect(a.hashCode, isNot(b.hashCode));
    });

    test('increment(): [..., 0,0,2] --> [...0,0,3]', () {
      var bytes = Uint8List(12);
      bytes[11] = 2;
      bytes = Nonce(bytes).increment().bytes;
      expect(bytes[11], equals(3));
      expect(bytes[10], equals(0));
      expect(bytes[9], equals(0));
    });

    test('increment(): [..., 0,2,255] --> [...0,3,0]', () {
      var bytes = Uint8List(12);
      bytes[11] = 255;
      bytes[10] = 2;
      bytes = Nonce(bytes).increment().bytes;
      expect(bytes[11], equals(0));
      expect(bytes[10], equals(3));
      expect(bytes[9], equals(0));
    });

    test('increment(): [..., 2,255,255] --> [...3,0,0]', () {
      var bytes = Uint8List(12);
      bytes[11] = 255;
      bytes[10] = 255;
      bytes[9] = 2;
      bytes = Nonce(bytes).increment().bytes;
      expect(bytes[11], equals(0));
      expect(bytes[10], equals(0));
      expect(bytes[9], equals(3));
    });

    test('"==" / hashCode', () {
      final value = Nonce(Uint8List.fromList([3, 1, 4]));
      final clone = Nonce(Uint8List.fromList([3, 1, 4]));
      final other0 = Nonce(Uint8List.fromList([3, 1, 999]));
      final other1 = Nonce(Uint8List.fromList([3, 1, 4, 999]));

      expect(value, clone);
      expect(value, isNot(other0));
      expect(value, isNot(other1));

      expect(value.hashCode, clone.hashCode);
      expect(value.hashCode, isNot(other0.hashCode));
      expect(value.hashCode, isNot(other1.hashCode));
    });

    test('toString() does not expose actual bytes', () {
      final a = Nonce(Uint8List(3));
      expect(a, isNot(contains('0')));
    });
  });
}
