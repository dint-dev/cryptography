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

import '../hex.dart';
import '../signature.dart';

void testEcdsa() {
  testSignatureAlgorithm(
    builder: () => Ecdsa.p256(Sha256()),
    otherTests: () {
      test('verify(): an example generated with Web Crypto in Chrome',
          () async {
        final keyPair = EcKeyPairData(
          type: KeyPairType.p256,
          d: hexToBytes(
            '0d 19 4a fc 8c 70 5c fb 02 8a 67 18 0f cc 67 79'
            '13 70 f8 d4 fa f7 fa 4f a8 65 87 47 93 1d ec 02',
          ),
          x: hexToBytes(
            'c0 d1 0a 39 40 c3 af 7e 6a 37 c8 2e f9 57 4f 2f'
            '0e 5b 22 d6 67 98 53 41 78 e1 c9 3e a9 f7 78 12',
          ),
          y: hexToBytes(
            'a8 2b ee 92 86 f7 a5 c0 f7 4d 3f 73 2b b8 e5 87'
            'f4 82 9e 75 47 6b e9 5b 35 db 64 c1 7f 46 30 01',
          ),
        );

        const message = <int>[1, 2, 3];
        final signature = Signature(
          hexToBytes(
            'da 6d b1 22 07 af 82 6e 1a bd 42 83 1b c2 cd cd'
            'd1 91 8e 18 12 b5 25 2a 84 ca 67 fe 65 01 e0 b5'
            '2b ec 19 ba 6a 35 40 d8 58 4e 0d eb 88 dd 49 08'
            '71 4c 28 20 ff d2 6e d2 cc d8 38 79 d4 7e 29 c3',
          ),
          publicKey: keyPair.publicKey,
        );

        expect(
          await signatureAlgorithm.verify(message, signature: signature),
          isTrue,
        );
      });
    },
  );
  testSignatureAlgorithm(
    builder: () => Ecdsa.p384(Sha384()),
    otherTests: () {
      test('verify(): an example generated with Web Crypto in Chrome',
          () async {
        final keyPair = EcKeyPairData(
          type: KeyPairType.p384,
          d: hexToBytes(
            '8a fe a9 3b de 9e c4 2f 06 64 04 86 68 92 13 bd'
            'e1 0d 20 1f 5e b4 41 f5 c3 c9 19 e2 eb b8 5f f3'
            'fa db 17 c6 e0 5f ae fc 90 72 28 12 48 74 28 b6',
          ),
          x: hexToBytes(
            '61 d2 cc 38 c0 39 ab b3 f9 0c 6b 53 bc 85 22 15'
            '8b c6 66 99 73 a0 8d 84 60 72 ef 40 71 5e 18 2f'
            '89 97 a3 b0 51 f2 58 2f 30 c2 e1 6a f9 7a f5 88',
          ),
          y: hexToBytes(
            'd1 8c 35 11 14 f5 a7 7b 34 25 e4 fc 61 df a6 ae'
            '42 91 1a 2f 6b ed 41 87 d2 4d 75 64 48 ed 0d d6'
            '26 c9 84 35 59 6c 3e 00 a3 d3 dd e5 d7 8f 8d a2',
          ),
        );

        const message = <int>[1, 2, 3];
        final signature = Signature(
          hexToBytes(
            'b0 4b e9 02 dc d8 01 58 42 c0 e4 57 ce 07 f6 05'
            '59 3f 9c ee dc ff 0d da a6 8f d6 1f 90 df 51 ab'
            'a5 11 66 3f cb a5 ab a9 cc 59 ac 31 e8 35 18 9a'
            '33 14 f7 1c 73 6c fc 3c 88 79 12 8d 7c e7 9d ba'
            'd7 cc a4 e7 27 64 5d 00 81 d8 ea be 47 85 41 ef'
            'ca 07 f1 95 8a 9b c7 b3 0e 02 af 21 5c 59 5a 22',
          ),
          publicKey: keyPair.publicKey,
        );

        expect(
          await signatureAlgorithm.verify(message, signature: signature),
          isTrue,
        );
      });
    },
  );
  testSignatureAlgorithm(
    builder: () => Ecdsa.p521(Sha512()),
    otherTests: () {
      test('verify(): an example generated with Web Crypto in Chrome',
          () async {
        final keyPair = EcKeyPairData(
          type: KeyPairType.p521,
          d: hexToBytes(
            '01 3a 89 00 c3 11 f2 ff 89 ec 31 d6 a0 08 cb c5'
            '2a 05 8b 0c 28 22 0f 7e 9c 42 36 a3 a5 36 57 b9'
            '36 2d f2 22 43 58 6f ae b4 4c 60 3c a4 a5 82 8c'
            '24 36 bf 8f b2 17 20 3a 3e 28 9e b7 17 0a 11 8c'
            'ed 55',
          ),
          x: hexToBytes(
            '00 cf 0f 20 cd d8 64 ed 61 a9 77 80 47 38 0d d6'
            '3e 5f 7e 56 33 b4 27 fd 74 ee c2 96 07 1c 89 cd'
            '5a 37 8d de 91 61 a1 44 55 4a 3a 39 88 54 93 b0'
            'ba 28 ba b4 4e 14 9c d2 c6 a1 c0 de 9d a8 d2 f6'
            '99 71',
          ),
          y: hexToBytes(
            '00 39 19 52 e4 bc 53 44 8e 42 15 13 8c ba ec ff'
            'a4 e9 5d f9 31 75 b3 55 ba 8c 79 1c ae a0 87 db'
            '30 69 42 d0 e4 33 b8 ec a3 7f 22 4a 8a 71 9a 3e'
            'f4 75 36 95 9a eb d1 73 f1 08 61 e5 12 ae 0d 1d'
            '45 b1',
          ),
        );

        const message = <int>[1, 2, 3];
        final signature = Signature(
          hexToBytes(
            '01 5a ab 45 c3 dc 90 7b 98 27 cd a1 ea 4d 8c 72'
            '5b 4b da 63 7b d8 7a 25 f3 2d 87 4a 7b 1d bb c3'
            '0c 9d e5 87 81 70 6e a7 45 a2 af 5c 3f 8f fa f3'
            'de b4 57 6a 65 64 7d 90 78 a0 03 d6 d7 69 ad fc'
            'f9 8b 01 82 b3 a9 81 4a 8c 88 0f f8 fa 1a 21 a2'
            'ae dd ff 64 d8 96 2f 25 1c 41 cc 97 49 a8 84 75'
            'd2 9d 9d 6e cd 40 f1 8a 6e ad 92 e4 af 6e b3 dd'
            'd5 15 b7 56 2e 48 38 84 2a 98 dd f3 22 f3 d2 ed'
            '0c 7b f5 4c',
          ),
          publicKey: keyPair.publicKey,
        );

        expect(
          await signatureAlgorithm.verify(message, signature: signature),
          isTrue,
        );
      });
    },
  );
}
