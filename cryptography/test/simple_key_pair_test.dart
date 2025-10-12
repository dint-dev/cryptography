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
  group('SimpleKeyPairData:', () {
    test('destroy()', () {
      final value = SimpleKeyPairData(
        [1, 2, 3],
        publicKey: SimplePublicKey([4, 5, 6], type: KeyPairType.ed25519),
        type: KeyPairType.ed25519,
      );

      // Copy
      final copy = value.copy();
      expect(value, copy);

      // Destroy
      expect(value.hasBeenDestroyed, isFalse);
      value.destroy();
      expect(value.hasBeenDestroyed, isTrue);
      value.destroy(); // Should be idempotent

      // Accessing bytes should fail.
      expect(() => value.bytes, throwsStateError);

      // Equality should not be affected.
      expect(value, copy);

      // Debug label should not be affected.
      expect(value.debugLabel, copy.debugLabel);
    });
    test('"==" / hashCode', () {
      final value = SimpleKeyPairData(
        [1],
        publicKey: SimplePublicKey([2], type: KeyPairType.ed25519),
        type: KeyPairType.ed25519,
      );
      final clone = SimpleKeyPairData(
        [1],
        publicKey: SimplePublicKey([2], type: KeyPairType.ed25519),
        type: KeyPairType.ed25519,
      );
      final other0 = SimpleKeyPairData(
        [1],
        publicKey: SimplePublicKey(
          [9999], // Different public key
          type: KeyPairType.ed25519,
        ),
        type: KeyPairType.ed25519,
      );
      final other1 = SimpleKeyPairData(
        [1],
        publicKey: SimplePublicKey([2], type: KeyPairType.ed25519),
        type: KeyPairType.x25519, // Different type
      );

      expect(value, clone);
      expect(value, isNot(other0));
      expect(value, isNot(other1));

      expect(value.hashCode, clone.hashCode);
      expect(value.hashCode, isNot(other0.hashCode));
      expect(value.hashCode, isNot(other1.hashCode));
    });

    test('toString() shows public key', () {
      final value = SimpleKeyPairData(
        [1],
        publicKey: SimplePublicKey([2], type: KeyPairType.ed25519),
        type: KeyPairType.ed25519,
      );
      expect(
        value.toString(),
        'SimpleKeyPairData(...,'
        ' publicKey: SimplePublicKey([2],'
        ' type: KeyPairType.ed25519))',
      );
    });

    test('toString() shows public key and debug label', () {
      final value = SimpleKeyPairData(
        [0, 1],
        publicKey: SimplePublicKey([2, 3], type: KeyPairType.ed25519),
        type: KeyPairType.ed25519,
        debugLabel: 'my key',
      );
      expect(
        value.toString(),
        'SimpleKeyPairData(...,'
        ' publicKey: SimplePublicKey([2,3],'
        ' type: KeyPairType.ed25519),'
        ' debugLabel: "my key")',
      );
    });
  });
}
