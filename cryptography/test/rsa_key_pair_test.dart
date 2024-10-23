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
  group('RsaKeyPairData:', () {
    test('"==" / hashCode', () {
      final value = RsaKeyPairData(
        d: [1],
        e: [2],
        n: [3],
        p: [4],
        q: [5],
      );
      final clone = RsaKeyPairData(
        d: [1],
        e: [2],
        n: [3],
        p: [4],
        q: [5],
      );
      final other0 = RsaKeyPairData(
        d: [9999],
        e: [2],
        n: [3],
        p: [4],
        q: [5],
      );
      final other1 = RsaKeyPairData(
        d: [1],
        e: [9999],
        n: [3],
        p: [4],
        q: [5],
      );
      final other2 = RsaKeyPairData(
        d: [1],
        e: [2],
        n: [9999],
        p: [4],
        q: [5],
      );
      final other3 = RsaKeyPairData(
        d: [1],
        e: [2],
        n: [3],
        p: [9999],
        q: [5],
      );
      final other4 = RsaKeyPairData(
        d: [1],
        e: [2],
        n: [3],
        p: [4],
        q: [9999],
      );

      expect(value, clone);
      expect(value, isNot(other0));
      expect(value, isNot(other1));
      expect(value, isNot(other2));
      expect(value, isNot(other3));
      expect(value, isNot(other4));

      expect(value.hashCode, clone.hashCode);
      expect(value.hashCode, isNot(other0.hashCode));
      expect(value.hashCode, isNot(other1.hashCode));
      expect(value.hashCode, isNot(other2.hashCode));
    });

    test('toString() does not expose actual bytes', () {
      final value = RsaKeyPairData(
        d: [1],
        e: [2],
        n: [3],
        p: [4],
        q: [5],
      );
      expect(value.toString(), 'RsaKeyPairData(...)');
    });
  });

  group('RsaPublicKey:', () {
    test('"==" / hashCode', () {
      final value = RsaPublicKey(
        e: [1],
        n: [2],
      );
      final clone = RsaPublicKey(
        e: [1],
        n: [2],
      );
      final other0 = RsaPublicKey(
        e: [9999],
        n: [2],
      );
      final other1 = RsaPublicKey(
        e: [1],
        n: [9999],
      );

      expect(value, clone);
      expect(value, isNot(other0));
      expect(value, isNot(other1));

      expect(value.hashCode, clone.hashCode);
      expect(value.hashCode, isNot(other0.hashCode));
      expect(value.hashCode, isNot(other1.hashCode));
    });

    test('toString() does not expose actual bytes', () {
      final value = RsaPublicKey(
        e: [1],
        n: [2, 3, 4, 5],
      );
      expect(
          value.toString(), 'RsaPublicKey(\n  e: [1],\n  n: [..., 4, 5],\n)');
    });
  });
}
