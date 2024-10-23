// Copyright 2019-2022 Gohilla.
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

import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:cryptography_plus/dart.dart';
import 'package:cryptography_plus/src/utils.dart';
import 'package:test/test.dart';

void main() {
  group('DartCryptography:', () {
    _testCryptography((random) => DartCryptography(random: random));
  });
  group('BrowserCryptography:', () {
    _testCryptography((random) => BrowserCryptography(random: random));
  });
}

const _first32 = '2b 1f 4d 63 94 da cb 7a 7b 08 59 a0 77 b0 56 7e\n'
    'd2 8a b0 e1 16 4c 87 ea 50 81 12 f2 29 32 18 3d';

const _nonce12 = '2c 84 29 c7 9e 2f 3e 39 44 ec 7b 6d';

const _nonce16 = '2c 84 29 c7 9e 2f 3e 39 44 ec 7b 6d bb b6 6b 0d';
const _nonce24 = '2c 84 29 c7 9e 2f 3e 39 44 ec 7b 6d bb b6 6b 0d\n'
    'ac 29 fc a6 e4 13 da 78';
Cryptography Function(Random? random) cryptographyFactory =
    (random) => BrowserCryptography(random: random);

void _testCipher({
  required Cipher Function() cipher,
  required String secretKeyHex,
  required String nonceHex,
}) {
  group('${cipher()}:', () {
    test('manual random number generator', () async {
      Cryptography.instance = cryptographyFactory(_TestRandom());
      final algorithm = cipher();
      final secretKey = await algorithm.newSecretKey();
      final secretKeyBytes = await secretKey.extractBytes();
      final nonceBytes = algorithm.newNonce();
      expect(
        hexFromBytes(secretKeyBytes),
        secretKeyHex,
      );
      expect(
        hexFromBytes(nonceBytes),
        nonceHex,
        reason:
            'Nonce length ${nonceBytes.length}, expected nonce length ${algorithm.nonceLength}',
      );
      final secretBox = await algorithm.encrypt(
        [1, 2, 3],
        secretKey: secretKey,
      );
      final clearText = await algorithm.decrypt(
        secretBox,
        secretKey: secretKey,
      );
      expect(clearText, [1, 2, 3]);
    });
  });
}

void _testCryptography(Cryptography Function(Random? random) f) {
  setUp(() {
    cryptographyFactory = f;
    Cryptography.instance = cryptographyFactory(null);
  });
  _testCipher(
    cipher: () => AesCbc.with256bits(macAlgorithm: MacAlgorithm.empty),
    secretKeyHex: _first32,
    nonceHex: _nonce16,
  );
  _testCipher(
    cipher: () => AesCtr.with256bits(macAlgorithm: MacAlgorithm.empty),
    secretKeyHex: _first32,
    nonceHex: _nonce16,
  );
  _testCipher(
    cipher: () => AesGcm.with256bits(),
    secretKeyHex: _first32,
    nonceHex: _nonce12,
  );
  _testCipher(
    cipher: () => Chacha20(macAlgorithm: MacAlgorithm.empty),
    secretKeyHex: _first32,
    nonceHex: _nonce12,
  );
  _testCipher(
    cipher: () => Chacha20.poly1305Aead(),
    secretKeyHex: _first32,
    nonceHex: _nonce12,
  );
  _testCipher(
    cipher: () => Xchacha20(macAlgorithm: MacAlgorithm.empty),
    secretKeyHex: _first32,
    nonceHex: _nonce24,
  );
  _testCipher(
    cipher: () => Xchacha20.poly1305Aead(),
    secretKeyHex: _first32,
    nonceHex: _nonce24,
  );

  test('${Ed25519()}:', () async {
    Cryptography.instance = cryptographyFactory(_TestRandom());
    final algorithm = Ed25519();
    final keyPair = await algorithm.newKeyPair();
    final privateKey = await keyPair.extractPrivateKeyBytes();
    expect(
      hexFromBytes(privateKey),
      _first32,
    );

    //
    // We test signature too because some implementations like Apple CryptoKit
    // compute non-deterministic signatures.
    //
    final signature = await algorithm.sign(Uint8List(100), keyPair: keyPair);
    expect(
      hexFromBytes(signature.bytes),
      'f2 01 0a 05 cf 95 16 a8 2b f7 f0 1e 16 66 9f d9\n'
      '90 a2 d6 91 0d 10 28 77 b6 43 16 56 b5 2f 79 23\n'
      '48 27 07 f9 40 a0 62 6c 0d e3 50 d8 ba 16 db 58\n'
      '89 68 2b ad 02 c5 62 bc 0d ef ef 8a e3 fb 00 06',
    );
    expect(
      hexFromBytes((signature.publicKey as SimplePublicKey).bytes),
      'ee c6 67 3c 80 1d 02 97 9a 50 c0 f3 ec ea 4e f4\n'
      '66 b2 2e ba f4 3d c5 9f 25 fe eb f3 ad 2d 55 f6',
    );
  });

  test('${X25519()}:', () async {
    Cryptography.instance = cryptographyFactory(_TestRandom());
    final privateKey =
        await (await X25519().newKeyPair()).extractPrivateKeyBytes();
    expect(
      hexFromBytes(privateKey),
      '28 1f 4d 63 94 da cb 7a 7b 08 59 a0 77 b0 56 7e\n'
      'd2 8a b0 e1 16 4c 87 ea 50 81 12 f2 29 32 18 7d',
    );
  });

  // test('${Ecdsa.p256(Sha256())}:', () async {
  //   Cryptography.instance = cryptographyFactory(_TestRandom());
  //   final algorithm = Ecdsa.p256(Sha256());
  //   final keyPair = await algorithm.newKeyPair();
  //   final privateKey = await keyPair.extract();
  //   expect(
  //     hexFromBytes(privateKey.d),
  //     '',
  //   );
  //
  //   final signature = await algorithm.sign(Uint8List(100), keyPair: keyPair);
  //   expect(
  //     hexFromBytes(signature.bytes),
  //     '',
  //   );
  //   expect(
  //     hexFromBytes((signature.publicKey as SimplePublicKey).bytes),
  //     '',
  //   );
  // });
  //
  // test('${Ecdh.p256(length: 32)}:', () async {
  //   Cryptography.instance = cryptographyFactory(_TestRandom());
  //   final algorithm = Ecdh.p256(length: 32);
  //   final keyPair = await algorithm.newKeyPair();
  //   final privateKey = await keyPair.extract();
  //   expect(
  //     hexFromBytes(privateKey.d),
  //     '',
  //   );
  // });
}

// XorShift
//
class _TestRandom implements Random {
  int _state = 2463534242;

  @override
  bool nextBool() => nextInt(2) != 0;

  @override
  double nextDouble() {
    return nextInt(uint32mask + 1) / (uint32mask + 1);
  }

  @override
  int nextInt(int max) {
    if (max < 0 || max > (uint32mask + 1)) {
      throw ArgumentError.value(max);
    }
    var x = _state;
    x ^= uint32mask & (x << 13);
    x ^= x >> 17;
    x ^= uint32mask & (x << 5);
    _state = x;
    return x % max;
  }
}
