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
  group('EcKeyPairData:', () {
    test('"==" / hashCode', () {
      final value = EcKeyPairData(
        d: [1],
        x: [2],
        y: [3],
        type: KeyPairType.p256,
      );
      final clone = EcKeyPairData(
        d: [1],
        x: [2],
        y: [3],
        type: KeyPairType.p256,
      );
      final other0 = EcKeyPairData(
        d: [1],
        x: [9999], // Different x
        y: [3],
        type: KeyPairType.p256,
      );
      final other1 = EcKeyPairData(
        d: [1],
        x: [2],
        y: [9999], // Different y
        type: KeyPairType.p256,
      );
      final other2 = EcKeyPairData(
        d: [1],
        x: [2],
        y: [3],
        type: KeyPairType.p384, // Different type
      );

      expect(value, clone);
      expect(value, isNot(other0));
      expect(value, isNot(other1));
      expect(value, isNot(other2));

      expect(value.hashCode, clone.hashCode);
      expect(value.hashCode, isNot(other0.hashCode));
      expect(value.hashCode, isNot(other1.hashCode));
      expect(value.hashCode, isNot(other2.hashCode));
    });

    test('toString()', () {
      final value = EcKeyPairData(
        d: [1],
        x: [2],
        y: [3],
        type: KeyPairType.p256,
      );
      expect(value.toString(), 'EcKeyPairData(..., type: KeyPairType.p256)');
    });
  });

  group('EcPublicKey:', () {
    test('"==" / hashCode', () {
      final value = EcPublicKey(
        x: [1],
        y: [2],
        type: KeyPairType.p256,
      );
      final clone = EcPublicKey(
        x: [1],
        y: [2],
        type: KeyPairType.p256,
      );
      final other0 = EcPublicKey(
        x: [9999],
        y: [2],
        type: KeyPairType.p256,
      );
      final other1 = EcPublicKey(
        x: [1],
        y: [9999],
        type: KeyPairType.p256,
      );
      final other2 = EcPublicKey(
        x: [1],
        y: [2],
        type: KeyPairType.p384,
      );

      expect(value, clone);
      expect(value, isNot(other0));
      expect(value, isNot(other1));
      expect(value, isNot(other2));

      expect(value.hashCode, clone.hashCode);
      expect(value.hashCode, isNot(other0.hashCode));
      expect(value.hashCode, isNot(other1.hashCode));
      expect(value.hashCode, isNot(other2.hashCode));
    });

    test('toString()', () {
      final value = EcPublicKey(
        x: [1, 2],
        y: [3, 4],
        type: KeyPairType.p256,
      );
      expect(value.toString(),
          'EcPublicKey(x: [1,2], y: [3,4], type: KeyPairType.p256)');
    });
  });
}
