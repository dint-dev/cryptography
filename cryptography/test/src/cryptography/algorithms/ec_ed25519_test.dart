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

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/utils.dart';
import 'package:test/test.dart';

void main() {
  group('ed25519:', () {
    group('Test vectors from RFC 8032:', () {
      test('vector #1', () {
        // ---------------------------------------------------------------------
        // The following constants are test vectors from RFC 8032:
        // https://tools.ietf.org/html/rfc8032
        // ---------------------------------------------------------------------
        final privateKey = PrivateKey(hexToBytes(
          '9d61b19deffd5a60ba844af492ec2cc4'
          '4449c5697b326919703bac031cae7f60',
        ));
        final publicKey = PublicKey(hexToBytes(
          'd75a980182b10ab7d54bfed3c964073a'
          '0ee172f3daa62325af021a68f707511a',
        ));
        final message = const <int>[];
        final signatureBytes = hexToBytes(
          'e5564300c360ac729086e2cc806e828a'
          '84877f1eb8e5d974d873e06522490155'
          '5fb8821590a33bacc61e39701cf9b46b'
          'd25bf5f0595bbe24655141438e7a100b',
        );
        // ---------------------------------------------------------------------
        // End of constants from RFC 8032
        // ---------------------------------------------------------------------

        final keyPair = KeyPair(privateKey: privateKey, publicKey: publicKey);
        final actualSignature = ed25519.signSync(message, keyPair);
        expect(actualSignature.bytes, signatureBytes);
        expect(actualSignature.publicKey, publicKey);

        // Correct signature
        expect(
          ed25519.verifySync(message, actualSignature),
          isTrue,
        );

        // Wrong signature
        final otherSignature = Signature(
          actualSignature.bytes,
          publicKey: PublicKey(Uint8List(publicKey.bytes.length)),
        );
        expect(
          ed25519.verifySync(message, otherSignature),
          isFalse,
        );
      });

      test('vector #2', () {
        // ---------------------------------------------------------------------
        // The following constants are test vectors from RFC 8032:
        // https://tools.ietf.org/html/rfc8032
        // ---------------------------------------------------------------------

        final privateKey = PrivateKey(hexToBytes(
          '4ccd089b28ff96da9db6c346ec114e0f'
          '5b8a319f35aba624da8cf6ed4fb8a6fb',
        ));
        final publicKey = PublicKey(hexToBytes(
          '3d4017c3e843895a92b70aa74d1b7ebc'
          '9c982ccf2ec4968cc0cd55f12af4660c',
        ));
        final message = const <int>[0x72];
        final signatureBytes = hexToBytes(
          '92a009a9f0d4cab8720e820b5f642540'
          'a2b27b5416503f8fb3762223ebdb69da'
          '085ac1e43e15996e458f3613d0f11d8c'
          '387b2eaeb4302aeeb00d291612bb0c00',
        );
        // ---------------------------------------------------------------------
        // End of constants from RFC 8032
        // ---------------------------------------------------------------------

        final keyPair = KeyPair(privateKey: privateKey, publicKey: publicKey);
        final actualSignature = ed25519.signSync(message, keyPair);
        expect(actualSignature.bytes, signatureBytes);
        expect(actualSignature.publicKey, publicKey);

        // Correct signature
        expect(ed25519.verifySync(message, actualSignature), isTrue);

        // Wrong signature
        final otherSignature = Signature(
          actualSignature.bytes,
          publicKey: PublicKey(Uint8List(publicKey.bytes.length)),
        );
        expect(
          ed25519.verifySync(message, otherSignature),
          isFalse,
        );
      });
    });
  }, skip: 'ed25519 tests do not pass yet');
}
