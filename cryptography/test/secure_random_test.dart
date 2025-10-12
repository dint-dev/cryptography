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

import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:test/test.dart';

void main() {
  group('SecureRandom.instance', () {
    test('toString()', () {
      expect(SecureRandom.fast.toString(), 'SecureRandom()');
    });

    test('random', () {
      final random = SecureRandom.fast;
      final set = <int>{};
      for (var i = 0; i < 10000; i++) {
        set.add(random.nextUint32());
      }
      expect(set.length, greaterThan(9900));
    });
  });

  group('SecureRandom.forTesting(...):', () {
    test('example', () {
      final random = SecureRandom.forTesting();
      expect(random.nextUint32(), 3150129412);
      expect(random.nextUint32(), 343203913);
      expect(random.nextUint32(), 2777219198);
    });

    test('example with non-default seed', () {
      final random = SecureRandom.forTesting(seed: 1);
      expect(random.nextUint32(), 663495753);
      expect(random.nextUint32(), 257774224);
      expect(random.nextUint32(), 4279763603);
    });

    test('isSecure', () {
      expect(
        SecureRandom.forTesting().isSecure,
        isFalse,
      );
    });

    test('toString()', () {
      expect(
        SecureRandom.forTesting().toString(),
        'SecureRandom.forTesting(seed: 0)',
      );
    });
  });

  group('SecureRandom', () {
    final random = SecureRandom.fast;

    test('nextBool', () {
      const n = 1000;
      var trueCount = 0;
      for (var i = 0; i < n; i++) {
        if (random.nextBool()) {
          trueCount++;
        }
      }
      expect(trueCount, greaterThan(n ~/ 3));
    });

    test('nextInt', () {
      const n = 1000;
      final counts = <int, int>{};
      for (var i = 0; i < n; i++) {
        final x = random.nextInt(3);
        expect(x, greaterThanOrEqualTo(0));
        expect(x, lessThanOrEqualTo(2));
        counts[x] = (counts[x] ?? 0) + 1;
      }
      final count0 = counts[0] ?? 0;
      final count1 = counts[1] ?? 0;
      final count2 = counts[2] ?? 0;
      expect(count0, greaterThan(n ~/ 4));
      expect(count1, greaterThan(n ~/ 4));
      expect(count2, greaterThan(n ~/ 4));
    });

    test('nextUint52', () {
      const n = 1000;
      for (var i = 0; i < n; i++) {
        final x = random.nextDouble();
        expect(x, greaterThanOrEqualTo(0.0));
        expect(x, lessThan(1.0));
      }
    });
    test('nextUint52', () {
      const n = 1000;

      var countOf51bitIntegers = 0;
      for (var i = 0; i < n; i++) {
        final x = random.nextUint52();
        expect(x, isNonNegative);
        expect(x, lessThan(_bit52));
        expect(x.toDouble().toInt(), x);
        if (x > _bit52 ~/ 2) {
          countOf51bitIntegers++;
        }
      }
      expect(countOf51bitIntegers, greaterThan(100));
    });
  });
}

int _bit16 = 0x10000;
int _bit32 = 0x100000000;

int _bit52 = (1 << 4) * _bit16 * _bit32;
