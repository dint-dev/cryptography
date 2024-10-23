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

import 'dart:typed_data';

import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:test/test.dart';

void main() {
  group('SecretKey:', () {
    SecretKey f(List<int> value) => SecretKey(
          value,
        );

    test('destroy()', () {
      final value = SecretKeyData([1, 2, 3], debugLabel: 'abc');

      // Copy
      final copy = value.copy();
      expect(copy, value);
      expect(copy.bytes, value.bytes);
      expect(copy.debugLabel, value.debugLabel);

      // Destroy
      expect(value.hasBeenDestroyed, isFalse);
      value.destroy();
      expect(value.hasBeenDestroyed, isTrue);
      value.destroy(); // Should be idempotent

      // Accessing bytes should fail.
      expect(() => value.bytes, throwsStateError);

      // Equality should not be affected.
      expect(value, isNot(copy));

      // Debug label should not be affected.
      expect(value.debugLabel, copy.debugLabel);
    });

    test('"==" / hashCode', () {
      final value = f([3, 1, 4]);
      final clone = f([3, 1, 4]);
      final other0 = f([3, 1, 999]);
      final other1 = f([3, 1, 4, 999]);

      expect(value, clone);
      expect(value, isNot(other0));
      expect(value, isNot(other1));

      expect(value.hashCode, clone.hashCode);
      expect(value.hashCode, isNot(other0.hashCode));
      expect(value.hashCode, isNot(other1.hashCode));
    });

    test('toString() does not expose actual bytes', () {
      final a = f([0, 0, 0]);
      expect(a, isNot(contains('0')));
    });
  });

  group('SecretKeyData:', () {
    test('SecretKeyData([...])', () {
      final inputs = [
        [42, 43, 44],
        Uint8List.fromList([42, 43, 44])
      ];
      for (var input in inputs) {
        final a = SecretKeyData(input);
        final capturedBytes = a.bytes;
        expect(capturedBytes, [42, 43, 44]);

        a.destroy();
        expect(input, [42, 43, 44]);
        expect(() => a.bytes, throwsStateError);
        expect(() => capturedBytes[0], throwsStateError);
      }
    });

    test('SecretKeyData([...], overwriteWhenDestroyed: true)', () {
      final inputs = [
        [42, 43, 44],
        Uint8List.fromList([42, 43, 44])
      ];
      for (var input in inputs) {
        final a = SecretKeyData(input, overwriteWhenDestroyed: true);
        final capturedBytes = a.bytes;
        expect(capturedBytes, [42, 43, 44]);

        a.destroy();
        expect(input, [0, 0, 0]);
        expect(() => a.bytes, throwsStateError);
        expect(() => capturedBytes[0], throwsStateError);
      }
    });

    test('SecretKeyData(const [...], overwriteWhenDestroyed: true)', () {
      const data = [42, 43, 44];
      final a = SecretKeyData(data, overwriteWhenDestroyed: true);
      final capturedBytes = a.bytes;
      expect(capturedBytes, [42, 43, 44]);

      a.destroy();
      expect(data, [42, 43, 44]);
      expect(() => a.bytes, throwsStateError);
      expect(() => capturedBytes[0], throwsStateError);
    });

    test('SecretKeyData.random()', () {
      final a = SecretKeyData.random(length: 32);
      final b = SecretKeyData.random(length: 32);
      expect(a.bytes, isNot(b.bytes));
      expect(a.hashCode, isNot(b.hashCode));
      expect(a, isNot(b));
      expect(a.debugLabel, isNull);
    });

    test('SecretKeyData.random(debugLabel: "x")', () {
      final a = SecretKeyData.random(length: 16, debugLabel: 'x');
      expect(a.debugLabel, 'x');
    });

    test('SecretKeyData.randomWithBuffer([...])', () {
      final original = [1, 2, 3, 4, 5, 6];
      final zeroes = Uint8List(original.length);
      final input = Uint8List.fromList(original);
      final key = SecretKeyData.randomWithBuffer(input);
      expect(input, isNot(original));
      expect(input, isNot(zeroes));

      key.destroy();
      expect(input, zeroes);
    });

    test('SecretKeyData.randomWithBuffer([...], overwriteWhenDestroyed: false)',
        () {
      final inputBefore = [1, 2, 3, 4, 5, 6];
      final zeroes = Uint8List(inputBefore.length);
      final input = Uint8List.fromList(inputBefore);
      final key = SecretKeyData.randomWithBuffer(
        input,
        overwriteWhenDestroyed: false,
      );
      expect(input, isNot(inputBefore));
      expect(input, isNot(zeroes));
      final keyBytesCopy = Uint8List.fromList(key.bytes);

      key.destroy();
      expect(input, keyBytesCopy);
    });

    test('"==" / hashCode', () {
      final value = SecretKey(Uint8List.fromList([3, 1, 4]));
      final clone = SecretKey(Uint8List.fromList([3, 1, 4]));
      final other0 = SecretKey(Uint8List.fromList([3, 1, 999]));
      final other1 = SecretKey(Uint8List.fromList([3, 1, 4, 999]));

      expect(value, clone);
      expect(value, isNot(other0));
      expect(value, isNot(other1));

      expect(value.hashCode, clone.hashCode);
      expect(value.hashCode, isNot(other0.hashCode));
      expect(value.hashCode, isNot(other1.hashCode));
    });

    test('toString()', () {
      final a = SecretKey([0, 0, 0]);
      expect(a.toString(), 'SecretKeyData(...)');
    });
  });
}
