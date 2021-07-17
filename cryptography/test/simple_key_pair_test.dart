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

import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';

void main() {
  group('SimpleKeyPairData:', () {
    test('"==" / hashCode', () {
      final value = SimpleKeyPairData(
        [1],
        publicKey: Future<SimplePublicKey>.value(
          SimplePublicKey([2], type: KeyPairType.ed25519),
        ),
        type: KeyPairType.ed25519,
      );
      final clone = SimpleKeyPairData(
        [1],
        publicKey: Future<SimplePublicKey>.value(
          SimplePublicKey([2], type: KeyPairType.ed25519),
        ),
        type: KeyPairType.ed25519,
      );
      final other0 = SimpleKeyPairData(
        [9999],
        publicKey: Future<SimplePublicKey>.value(
          SimplePublicKey([2], type: KeyPairType.ed25519),
        ),
        type: KeyPairType.ed25519,
      );
      final other1 = SimpleKeyPairData(
        [1],
        publicKey: Future<SimplePublicKey>.value(
          SimplePublicKey([2], type: KeyPairType.ed25519),
        ),
        type: KeyPairType.x25519,
      );

      expect(value, clone);
      expect(value, isNot(other0));
      expect(value, isNot(other1));

      expect(value.hashCode, clone.hashCode);
      expect(value.hashCode, isNot(other0.hashCode));
      expect(value.hashCode, isNot(other1.hashCode));
    });

    test('toString() shows only key type', () {
      final value = SimpleKeyPairData(
        [1],
        publicKey: Future<SimplePublicKey>.value(
          SimplePublicKey([2], type: KeyPairType.ed25519),
        ),
        type: KeyPairType.ed25519,
      );
      expect(
        value.toString(),
        'SimpleKeyPairData(..., type: KeyPairType.ed25519)',
      );
    });
  });

  group('SimplePublicKey:', () {
    test('"==" / hashCode', () {
      final value = SimplePublicKey(
        [1],
        type: KeyPairType.ed25519,
      );
      final clone = SimplePublicKey(
        [1],
        type: KeyPairType.ed25519,
      );
      final other0 = SimplePublicKey(
        [9999],
        type: KeyPairType.ed25519,
      );
      final other1 = SimplePublicKey(
        [1],
        type: KeyPairType.x25519,
      );

      expect(value, clone);
      expect(value, isNot(other0));
      expect(value, isNot(other1));

      expect(value.hashCode, clone.hashCode);
      expect(value.hashCode, isNot(other0.hashCode));
      expect(value.hashCode, isNot(other1.hashCode));
    });

    test('toString()', () {
      final value = SimplePublicKey(
        [1, 2],
        type: KeyPairType.ed25519,
      );
      expect(value.toString(),
          'SimplePublicKey([1,2], type: KeyPairType.ed25519)');
    });
  });
}
