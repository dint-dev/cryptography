// Copyright 2019 Gohilla (opensource@gohilla.com).
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
import 'package:raw/raw.dart';
import 'package:test/test.dart';

void main() {
  group('X25519:', () {
    test('Test vectors from RFC 7748', () async {
      // The following constants are from RFC 7748:
      // https://tools.ietf.org/html/rfc7748

      final aliceSecretKey = SecretKey(const DebugHexDecoder().convert(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
      ));
      final alicePublicKey = PublicKey(const DebugHexDecoder().convert(
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
      ));
      final bobSecretKey = SecretKey(const DebugHexDecoder().convert(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
      ));
      final bobPublicKey = PublicKey(const DebugHexDecoder().convert(
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
      ));
      final sharedSecret = SecretKey(const DebugHexDecoder().convert(
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
      ));

      // Test generating a public key (for Alice)
      expect(
        (await x25519.newKeyPairFromSeed(aliceSecretKey)).publicKey,
        alicePublicKey,
      );

      // Test generating a public key (for Bob)
      expect(
        (await x25519.newKeyPairFromSeed(bobSecretKey)).publicKey,
        bobPublicKey,
      );

      // Test generating a shared secret (for Alice)
      expect(
        (await x25519.sharedSecret(aliceSecretKey, bobPublicKey)),
        sharedSecret,
      );

      // Test generating a shared secret (for Bob)
      expect(
        (await x25519.sharedSecret(bobSecretKey, alicePublicKey)),
        sharedSecret,
      );
    });

    test("Test public key generation with 10 000 cycles", () {
      // A concise test that gives us confidence that fewer than 0.01% of
      // outputs are incorrect.

      const n = 10000;

      // Initial secret key
      var input = Uint8List(32);
      input[0] = 1;

      // 'n' times
      for (var i = 0; i < n; i++) {
        // Generate a public key
        final keyPair = x25519.newKeyPairFromSeed(SecretKey(input));

        // Use the output as the next input
        input = keyPair.publicKey.bytes;
      }

      // Public key after 'n' cycles
      final expected = Uint8List.fromList([
        // Generated from a correct implementation.
        138, 8, 200, 47, 95, 126, 210, 241,
        240, 215, 22, 64, 139, 230, 175, 228,
        225, 187, 38, 220, 231, 7, 114, 132,
        215, 244, 136, 80, 47, 52, 92, 15,
      ]);

      expect(input, equals(expected));
    });
  });
}
