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
import 'package:cryptography_test/key_exchange.dart';
import 'package:test/test.dart';

import '../hex.dart';

void testEcdh() {
  testKeyExchangeAlgorithm(
    builder: () => Ecdh.p256(length: 32),
    otherTests: () {
      test('Example (generated with Web Crypto in Chrome)', () async {
        final keyPair = EcKeyPairData(
          type: KeyPairType.p256,
          d: hexToBytes(
            'a3 8c 06 5e 78 b2 63 3b 78 02 00 20 26 7c b4 e1'
            '92 d1 b8 8c b1 c7 8b d8 62 c5 03 c3 2a 55 6f 46',
          ),
          x: hexToBytes(
            'dc 6c 45 c9 d8 26 d4 11 4f c9 8c 20 af b0 e7 3d'
            'f8 3e 2d 70 13 bd ce 52 ff fd cc fe 82 ca 41 62',
          ),
          y: hexToBytes(
            'e0 ed b1 6d 1f 5c 2b 8f b3 14 0c d8 e7 d0 1a 00'
            'de 56 9d 1c 3a 6e 8d a7 67 c6 42 13 df 86 bb 50',
          ),
        );

        final remotePublicKey = EcPublicKey(
          type: KeyPairType.p256,
          x: hexToBytes(
            'e8 37 6d 5e 8f 01 3b 62 d0 51 bf bf e0 b5 49 d4'
            '89 7f 24 c3 91 b3 52 f2 80 ee 7b 8d 92 cf 3c 41',
          ),
          y: hexToBytes(
            '88 d4 02 87 2f 71 71 5b f9 ad 58 f0 1b 42 18 f6'
            'f0 54 06 df 72 b8 61 e4 ae 5b 94 9d d7 2d 0b cb',
          ),
        );

        final expectedSecretKey = hexToBytes(
          '57 1b 70 14 dc fe 4b 27 b0 b4 44 e9 5d 06 e6 d1'
          '4f 87 8f 57 65 73 eb a1 6f d5 32 bf 2f d0 c3 db',
        );

        final actualSecretKey = await keyExchangeAlgorithm.sharedSecretKey(
          keyPair: keyPair,
          remotePublicKey: remotePublicKey,
        );
        expect(
          hexFromBytes(await actualSecretKey.extractBytes()),
          hexFromBytes(expectedSecretKey),
        );
      });
    },
  );
  testKeyExchangeAlgorithm(
    builder: () => Ecdh.p384(length: 32),
    otherTests: () {
      test('Example (generated with Web Crypto in Chrome)', () async {
        final keyPair = EcKeyPairData(
          type: KeyPairType.p384,
          d: hexToBytes(
            'a7 05 89 71 97 09 91 38 c3 46 69 89 78 9b 07 e0'
            '2a 16 5d 4a 29 1b e6 94 aa 9c ca 87 22 4f e8 ce'
            '5a 5b 78 52 10 59 c1 db 15 33 3f 9d 45 32 7e 3f',
          ),
          x: hexToBytes(
            '64 e3 98 06 a8 b2 28 e4 5f a2 5a 37 11 8c 90 30'
            'a4 f6 ce 39 ef 0b 96 14 08 7a e8 0b 15 1f 5c 7c'
            '71 6c 5b c1 aa 5f ca 2f d4 31 ff 9f 16 e5 44 53',
          ),
          y: hexToBytes(
            'dd 80 09 55 ca b0 ac 3d f5 0d cc f6 c4 32 80 8d'
            '01 36 f2 07 9f 75 59 1d 05 20 53 c4 b2 02 b9 8c'
            'e2 e0 cc 58 38 1b aa bc bb d7 4a 49 a1 cf f8 6a',
          ),
        );

        final remotePublicKey = EcPublicKey(
          type: KeyPairType.p384,
          x: hexToBytes(
            '92 55 2a b4 06 99 08 f3 da c4 ae e2 3c 0b cf ff'
            '03 08 cb b5 9c e7 86 79 8e d7 23 82 1b 1a 6a 3a'
            'de c4 df 07 c4 f2 05 91 d8 10 b3 12 0c fc 31 93',
          ),
          y: hexToBytes(
            '49 e9 96 d1 da 6c 6d d8 f1 74 28 87 12 d9 1c 09'
            '23 ee ca 5e bd d2 de 51 98 80 44 dc ec 71 cf 97'
            '3e a3 58 22 99 6a d4 5b 1f a5 ba 12 9b 45 50 77',
          ),
        );

        final expectedSecretKey = hexToBytes(
          '8c e8 b0 19 b5 80 ad ec 05 a6 35 18 0d de dd 68'
          'bf ad 25 ab 53 aa 23 c7 13 94 58 64 6b 0a 79 f6',
        );

        final actualSecretKey = await keyExchangeAlgorithm.sharedSecretKey(
          keyPair: keyPair,
          remotePublicKey: remotePublicKey,
        );
        expect(
          hexFromBytes(await actualSecretKey.extractBytes()),
          hexFromBytes(expectedSecretKey),
        );
      });
    },
  );
  testKeyExchangeAlgorithm(
    builder: () => Ecdh.p521(length: 32),
    otherTests: () {
      test('Example (generated with Web Crypto in Chrome)', () async {
        final keyPair = EcKeyPairData(
          type: KeyPairType.p521,
          d: hexToBytes(
            '00 86 ed 57 e2 70 93 53 cf b7 36 ac 35 a5 64 39'
            '5b 89 d7 1f 87 98 ee 16 e1 35 a9 11 64 e2 9c d9'
            'aa ba bd aa fc 7a a9 23 30 9b c7 1a 32 df 09 05'
            'ad 04 ba d4 13 9e bf 24 19 78 c5 58 93 2d 18 d1'
            'f7 83',
          ),
          x: hexToBytes(
            '00 07 c7 87 ef 1a 93 17 46 f6 4e 63 78 3d 61 10'
            'eb ae ed 06 13 d0 61 27 0c eb b9 88 2a 20 00 36'
            '22 10 ba 0b ee c2 54 d5 3a ba 52 b0 11 fa 4d 27'
            '28 6b 18 07 51 7f 30 57 04 45 32 5a ba 34 fc e0'
            'd3 65',
          ),
          y: hexToBytes(
            '00 2a 2d cc a0 bf 5a 1c d1 a7 0d 39 22 64 7e a1'
            '03 0c 67 b0 a9 7c e5 e5 7e 73 82 b1 11 90 b0 5f'
            '9d f7 cc bc f8 52 45 19 56 75 9e 2f 53 63 36 69'
            '10 93 05 1c a1 dc 10 53 47 5e bb a3 69 56 fb 78'
            '9d 01',
          ),
        );

        final remotePublicKey = EcPublicKey(
          type: KeyPairType.p521,
          x: hexToBytes(
            '01 18 00 5d 88 da 98 e4 cf bd 27 28 4d 8d a4 71'
            'a6 46 0d 49 72 d9 e7 32 f3 a0 41 15 09 c8 42 d4'
            '89 1f be f5 a9 4f 0a db 7e 4b 9f d9 c0 c7 c7 43'
            '90 97 c3 49 00 52 4c 88 e2 f3 16 30 b9 9c b8 78'
            '33 7f',
          ),
          y: hexToBytes(
            '01 f1 f5 9d 06 e5 d7 db a4 08 d1 50 c0 7c 94 f5'
            '73 7c 60 ce db cd d5 3a 5c f2 f1 30 95 9a 91 9c'
            '64 19 04 84 d9 bd 43 25 d1 17 4f 4a 48 3f 5e 78'
            '85 b4 04 92 e9 0e 61 13 11 cf 96 42 5f 8a 35 ab'
            '33 80',
          ),
        );

        final expectedSecretKey = hexToBytes(
          '01 06 64 1d a5 95 f8 59 58 f0 0d b2 34 ea 49 67'
          '26 ee 8e 1f f0 5c 3f 9e 82 c9 f0 8f 8d 1c 74 0a',
        );

        final actualSecretKey = await keyExchangeAlgorithm.sharedSecretKey(
          keyPair: keyPair,
          remotePublicKey: remotePublicKey,
        );
        expect(
          hexFromBytes(await actualSecretKey.extractBytes()),
          hexFromBytes(expectedSecretKey),
        );
      });
    },
  );
}
