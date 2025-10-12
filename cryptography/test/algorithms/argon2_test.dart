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

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:cryptography_plus/dart.dart';
import 'package:cryptography_plus/src/_internal/hex.dart';
import 'package:test/test.dart';

void main() {
  group('$DartArgon2id:', () {
    test('memory=1MB parallelism=1 iterations=1', () async {
      final algorithm = DartArgon2id(
        memory: 1000,
        parallelism: 1,
        iterations: 1,
        hashLength: 32,
      ).newState();
      final password = utf8.encode('password');
      final nonce = utf8.encode('nonce');
      final secret = utf8.encode("secret");
      final associatedData = utf8.encode("data");

      final stopwatch = Stopwatch()..start();
      final result = await algorithm.deriveKeyBytes(
        password: password,
        nonce: nonce,
        optionalSecret: secret,
        associatedData: associatedData,
      );
      stopwatch.stop();
      expect(stopwatch.elapsedMilliseconds, lessThan(10000));

      final expected = hexToBytes(
        '5d 00 7f 67 60 16 5c 8c e3 f0 7d 2c 5c bb 57 aa\n'
        'eb ea d5 69 e7 f6 d4 6a 63 03 16 1b 82 65 6e 87',
      );
      expect(
        hexFromBytes(result),
        hexFromBytes(expected),
      );
    });

    test('memory=64 parallelism=2 iterations=1 hashLength=32', () async {
      final algorithm = DartArgon2id(
        memory: 64,
        parallelism: 2,
        iterations: 1,
        hashLength: 32,
      );

      final expected = hexToBytes(
        'a2 e8 21 e1 6f c9 0a fc 60 7a 6f 71 c6 3c 23 45\n'
        'bf 14 5d da fe ae 0d 0f 5f 89 8a a4 74 67 b4 d4',
      );

      final actual = await (await algorithm.deriveKey(
        secretKey: SecretKey(utf8.encode('password')),
        nonce: utf8.encode('salt'),
        optionalSecret: utf8.encode("secret"),
        associatedData: utf8.encode("data"),
      ))
          .extractBytes();

      expect(
        hexFromBytes(actual),
        hexFromBytes(expected),
      );
    });

    test('memory=64 parallelism=1 iterations=2 hashLength=32', () async {
      final algorithm = DartArgon2id(
        memory: 64,
        parallelism: 1,
        iterations: 2,
        hashLength: 32,
      );

      final expected = hexToBytes(
        'e2 04 7b 57 6a e3 94 3c 86 0e 60 3c 7b c7 b1 e2\n'
        'd5 96 c4 0b 06 1e 79 ab 97 53 df f5 b6 83 46 42',
      );

      final actual = await (await algorithm.deriveKey(
        secretKey: SecretKey(utf8.encode('password')),
        nonce: utf8.encode('salt'),
        optionalSecret: utf8.encode("secret"),
        associatedData: utf8.encode("data"),
      ))
          .extractBytes();

      expect(
        hexFromBytes(actual),
        hexFromBytes(expected),
      );
    });

    test('memory=64 parallelism=1 iterations=1 hashLength=24', () async {
      final algorithm = DartArgon2id(
        memory: 64,
        parallelism: 1,
        iterations: 1,
        hashLength: 24,
      );

      final expected = hexToBytes(
        '1a e5 e5 10 78 35 10 5a 4f bc 96 b0 3b d1 41 42\n'
        'bd d1 b1 ed 7e 06 84 d4',
      );

      final actual = await (await algorithm.deriveKey(
        secretKey: SecretKey(utf8.encode('password')),
        nonce: utf8.encode('salt'),
        optionalSecret: utf8.encode("secret"),
        associatedData: utf8.encode("data"),
      ))
          .extractBytes();

      expect(
        hexFromBytes(actual),
        hexFromBytes(expected),
      );
    });
  });

  group('$DartArgon2State:', () {
    group('parameters are validated:', () {
      test('memory', () {
        expect(
          () => DartArgon2State(
            mode: DartArgon2Mode.argon2id,
            memory: 7,
            parallelism: 1,
            iterations: 1,
            hashLength: 32,
          ),
          throwsArgumentError,
        );
      });

      test('parallelism', () {
        expect(
          () => DartArgon2State(
            mode: DartArgon2Mode.argon2id,
            memory: 64,
            parallelism: 0,
            iterations: 1,
            hashLength: 32,
          ),
          throwsArgumentError,
        );
      });

      test('iterations', () {
        expect(
          () => DartArgon2State(
            mode: DartArgon2Mode.argon2id,
            memory: 64,
            parallelism: 1,
            iterations: 0,
            hashLength: 32,
          ),
          throwsArgumentError,
        );
      });

      test('hashLength', () {
        expect(
          () => DartArgon2State(
            mode: DartArgon2Mode.argon2id,
            memory: 64,
            parallelism: 1,
            iterations: 1,
            hashLength: 3,
          ),
          throwsArgumentError,
        );
      });
    });
    test('RFC 9106: Argon2d test vector', () async {
      final state = DartArgon2State(
        mode: DartArgon2Mode.argon2d,
        memory: 32, // 32 kB
        parallelism: 4,
        iterations: 3,
        hashLength: 32,
      );
      final actual = await state.deriveKeyBytes(
        password: List<int>.filled(32, 0x1),
        nonce: List<int>.filled(16, 0x2),
        optionalSecret: List<int>.filled(8, 0x3),
        associatedData: List<int>.filled(12, 0x4),
      );
      final expected = hexToBytes(
        '51 2b 39 1b 6f 11 62 97 53 71 d3 09 19 73 42 94\n'
        'f8 68 e3 be 39 84 f3 c1 a1 3a 4d b9 fa be 4a cb',
      );

      expect(
        hexFromBytes(actual),
        hexFromBytes(expected),
      );
    });

    test('RFC 9106: Argon2i test vector', () async {
      final state = DartArgon2State(
        mode: DartArgon2Mode.argon2i,
        memory: 32, // 32 kB
        parallelism: 4,
        iterations: 3,
        hashLength: 32,
      );
      final actual = await state.deriveKeyBytes(
        password: List<int>.filled(32, 0x1),
        nonce: List<int>.filled(16, 0x2),
        optionalSecret: List<int>.filled(8, 0x3),
        associatedData: List<int>.filled(12, 0x4),
      );
      final expected = hexToBytes(
        'c8 14 d9 d1 dc 7f 37 aa 13 f0 d7 7f 24 94 bd a1\n'
        'c8 de 6b 01 6d d3 88 d2 99 52 a4 c4 67 2b 6c e8',
      );

      expect(
        hexFromBytes(actual),
        hexFromBytes(expected),
      );
    });

    test('RFC 9106: Argon2id test vector', () async {
      final state = DartArgon2State(
        mode: DartArgon2Mode.argon2id,
        memory: 32,
        // 32 kB
        parallelism: 4,
        iterations: 3,
        hashLength: 32,
      );

      // Test pre-hashing digest
      final h0 = state.preHashingDigest(
        password: List<int>.filled(32, 0x1),
        nonce: List<int>.filled(16, 0x2),
        optionalSecret: List<int>.filled(8, 0x3),
        associatedData: List<int>.filled(12, 0x4),
      );
      final expectedH0 = hexToBytes(
        '28 89 de 48 7e b4 2a e5 00 c0 00 7e d9 25 2f 10'
        '69 ea de c4 0d 57 65 b4 85 de 6d c2 43 7a 67 b8'
        '54 6a 2f 0a cc 1a 08 82 db 8f cf 74 71 4b 47 2e'
        '94 df 42 1a 5d a1 11 2f fa 11 43 43 70 a1 e9 97',
      );
      expect(hexFromBytes(h0), hexFromBytes(expectedH0));

      final actual = await state.deriveKeyBytesFromPrehashingDigest(h0);
      final expected = hexToBytes(
        '0d 64 0d f5 8d 78 76 6c 08 c0 37 a3 4a 8b 53 c9 d0'
        '1e f0 45 2d 75 b6 5e b5 25 20 e9 6b 01 e6 59',
      );
      expect(hexFromBytes(actual), hexFromBytes(expected));
    });

    test('RFC 9106: Argon2id test vector (different `maxIsolates` values)',
        () async {
      for (var maxIsolates in const [0, 1, 2, 3, 4, 5, 6, 7, 8]) {
        final algorithm = DartArgon2id(
          memory: 32,
          parallelism: 4,
          iterations: 3,
          hashLength: 32,
          maxIsolates: maxIsolates,
          minBlocksPerSliceForEachIsolate: 1,
        );

        final state = algorithm.newState();
        expect(state.maxIsolates, maxIsolates);
        final isJs = 1.0 is int;
        if (isJs) {
          expect(state.isolateCount, 0);
        } else {
          switch (maxIsolates) {
            case 0:
              expect(state.isolateCount, 0);
              break;
            case 1:
              expect(state.isolateCount, 1);
              break;
            case 2:
              expect(state.isolateCount, 2);
              break;
            case 3:
              expect(state.isolateCount, 3);
              break;
            case 4:
              expect(state.isolateCount, 4);
              break;
            case 5:
              expect(state.isolateCount, 4);
              break;
            case 6:
              expect(state.isolateCount, 4);
              break;
            case 7:
              expect(state.isolateCount, 4);
              break;
            case 8:
              expect(state.isolateCount, 4);
              break;
          }
        }

        final actual = await state.deriveKeyBytes(
          password: List<int>.filled(32, 0x1),
          nonce: List<int>.filled(16, 0x2),
          optionalSecret: List<int>.filled(8, 0x3),
          associatedData: List<int>.filled(12, 0x4),
        );
        final expected = hexToBytes(
          '0d 64 0d f5 8d 78 76 6c 08 c0 37 a3 4a 8b 53 c9 d0'
          '1e f0 45 2d 75 b6 5e b5 25 20 e9 6b 01 e6 59',
        );
        expect(hexFromBytes(actual), hexFromBytes(expected));
      }
    });

    test('state can be reused', () async {
      final algorithm = DartArgon2id(
        memory: 32, // 32 kB
        parallelism: 4,
        iterations: 3,
        hashLength: 32,
      );

      final state = algorithm.newState();

      // Hash
      final hash = await state.deriveKeyBytes(
        password: List<int>.filled(32, 0x1),
        nonce: List<int>.filled(16, 0x2),
        optionalSecret: List<int>.filled(8, 0x3),
        associatedData: List<int>.filled(12, 0x4),
      );

      // Take some other hash
      final otherHash = await state.deriveKeyBytes(
        password: <int>[],
      );
      expect(otherHash, isNot(hash));

      // Same hash again
      final sameHash = await state.deriveKeyBytes(
        password: List<int>.filled(32, 0x1),
        nonce: List<int>.filled(16, 0x2),
        optionalSecret: List<int>.filled(8, 0x3),
        associatedData: List<int>.filled(12, 0x4),
      );

      expect(hexFromBytes(sameHash), hexFromBytes(hash));
    });

    test('getBlock()', () {
      final state = DartArgon2State(
        mode: DartArgon2Mode.argon2id,
        parallelism: 3,
        memory: 24,
        iterations: 1,
        hashLength: 16,
      );

      state.getBlock(lane: 0, slice: 0, index: 0);
      final lastBlock = state.getBlock(lane: 2, slice: 3, index: 1);
      expect(lastBlock.offsetInBytes + lastBlock.lengthInBytes, 24 * 1024);
    });

    test('initialize(...)', () {
      final state = DartArgon2State(
        mode: DartArgon2Mode.argon2id,
        parallelism: 1,
        memory: 8,
        iterations: 1,
        hashLength: 16,
      );

      state.initialize(
        h0: Uint8List.fromList(List<int>.filled(64, 1)),
      );

      final block0 = state.getBlock(lane: 0, slice: 0, index: 0);
      final block1 = state.getBlock(lane: 0, slice: 0, index: 1);
      final block2 = state.getBlock(lane: 0, slice: 0, index: 2);
      expect(block0[0], 2791158924);
      expect(block0[1], 1813049208);
      expect(block1[0], 3529607457);
      expect(block1[1], 971706456);
      expect(block2[0], 0);
      expect(block2[1], 0);
    });

    group('variableLengthHash(...)', () {
      final state = DartArgon2State(
        mode: DartArgon2Mode.argon2id,
        parallelism: 1,
        memory: 8,
        iterations: 1,
        hashLength: 16,
      );

      test('[1,2,3], length=32', () {
        final input = Uint8List.fromList([1, 2, 3]);
        final output = Uint8List(32);
        state.variableLengthHash(output: output, input: input);
        final expected = hexToBytes(
          'e9 5a 62 6c 57 9c 41 14 49 c0 23 92 ba 99 82 fc\n'
          'd1 9d 6c b4 32 fb c7 2a 82 43 2c 69 8c 7e 61 94',
        );
        expect(
          hexFromBytes(output),
          hexFromBytes(expected),
        );
      });

      test('[1,2,3], length=64', () {
        final input = Uint8List.fromList([1, 2, 3]);
        final output = Uint8List(64);
        state.variableLengthHash(output: output, input: input);
        final expected = hexToBytes(
          'fa 47 8f 2a 48 a2 f6 2e d8 df 48 25 62 c4 10 11\n'
          '34 9c cb 83 23 d1 0f 65 da 31 4e ec 06 28 ff 6a\n'
          'b8 a2 bf 75 c4 de b7 4c 25 ab 1b f9 00 2c 47 4c\n'
          '27 a2 80 b4 62 e6 33 9f 15 a5 a6 15 84 ae c6 41',
        );
        expect(
          hexFromBytes(output),
          hexFromBytes(expected),
        );
      });

      test('[1,2,3], length=96', () {
        final input = Uint8List.fromList([1, 2, 3]);
        final output = Uint8List(96);
        state.variableLengthHash(output: output, input: input);
        final expected = hexToBytes(
          '6d a2 8e af 2e d2 cb b4 f5 62 8b 77 04 41 43 e0\n'
          '25 fa 8e 5c 44 e7 c7 e4 d6 60 1e aa 54 e7 b0 ec\n'
          '63 93 eb aa 04 73 d3 a3 bc ef fb 11 57 3c b2 95\n'
          '8b c8 2e 78 fb a1 bc 84 a9 ca bc de 44 a0 6b f4\n'
          '9b ef 13 9a b8 c8 d3 f0 a6 f0 43 a1 b8 2d 35 04\n'
          'ef e2 32 22 78 95 25 03 11 2f 76 ee e8 9e c5 fe',
        );
        expect(
          hexFromBytes(output),
          hexFromBytes(expected),
        );
      });

      test('[1,2,3], length=256', () {
        final input = Uint8List.fromList([1, 2, 3]);
        final output = Uint8List(256);
        state.variableLengthHash(output: output, input: input);
        final expected = hexToBytes(
          '30 6a a5 81 d6 be 11 9c 92 e6 26 08 a5 66 a1 dc\n'
          '9a ba 0a f6 2f da 91 24 ce b1 51 9f c8 ca 24 46\n'
          '1f 09 b5 d0 b3 9a b5 5d 53 5f c7 0a 24 67 6d c1\n'
          '72 57 09 e4 5e f4 60 28 08 eb 7b 98 2f cc 3e 8f\n'
          '34 b1 66 b9 c6 99 8f c2 1d ec 0d 69 4d 3d 64 09\n'
          '83 4d 7d 9e be c0 18 bd d7 79 ac 81 64 9d f9 55\n'
          '28 8b 53 6f 6d c0 d3 8e 9a 4c 2e 40 8a 31 0e 12\n'
          '76 f8 13 57 e6 78 1a 5e 15 b2 56 d8 14 45 ac 0a\n'
          'd5 de c7 64 72 78 4e 10 db 35 25 9b da 94 00 76\n'
          '21 45 d0 f0 75 19 b3 d0 47 cb 3f 2d 0a c5 be 53\n'
          '8f af 53 13 dc e3 92 e7 1c f5 93 f1 d3 6e 6f 39\n'
          'f5 1d 6f b0 75 bf 6d 85 f9 68 41 57 7a 54 86 40\n'
          'eb ec 83 3a 7b d1 73 64 e1 cc ca a6 76 c0 8b 89\n'
          'ed 56 4e a2 bf 76 2b 2f d6 69 fe c1 ce 0f f6 59\n'
          'ef 45 5a 14 a0 90 e6 e0 76 32 e9 22 46 20 af c2\n'
          'd6 f4 a3 25 29 5f ad 31 15 f7 e0 c8 47 de a8 f4',
        );
        expect(
          hexFromBytes(output),
          hexFromBytes(expected),
        );
      });

      test('[1,2,3], length=257', () {
        final input = Uint8List.fromList([1, 2, 3]);
        final output = Uint8List(257);
        state.variableLengthHash(output: output, input: input);
        final expected = hexToBytes(
          '95 cf 8e 88 a7 00 04 e6 d8 bb e2 cf 54 1c 77 32\n'
          'f2 82 08 58 3a 62 4a 83 a8 ed a5 76 7d 67 3c 8a\n'
          '1b ed 45 68 9e d3 17 61 31 c6 9c 4e 0f 2a 29 f5\n'
          '91 38 5e a1 38 f7 1e 42 1f 11 ab f3 88 03 2b 31\n'
          'fd b0 33 49 9d b9 3b 78 dd 99 94 95 26 e2 61 fd\n'
          '38 f0 a7 f3 b1 6c a9 a7 69 db 05 c4 d6 a2 38 60\n'
          'fa 00 bf f3 f8 01 23 79 31 f3 6a 99 40 12 15 31\n'
          '46 61 27 59 1b a8 46 82 2d 30 ed 5e 0a c5 d2 d6\n'
          '58 67 e3 cc 81 cc d5 8d ca 02 ef 1d e9 8b 96 be\n'
          'f7 5e e7 8a a6 b0 d7 a8 ef 52 9c a9 2f 23 99 2e\n'
          'e8 8a 3c 16 3a db 73 62 19 bb cf 05 8e ad c2 e4\n'
          '52 86 b6 10 b0 c8 d3 e4 c4 44 71 aa 89 18 3a 2f\n'
          '17 d4 77 01 0e d4 0b 11 c3 a3 46 61 da 26 88 3d\n'
          '32 ed c5 ed 9a 5d 15 a7 06 1a 9c 23 8e 94 21 18\n'
          'd5 27 ac 4e 0f c5 e3 06 0c 22 dd 7b 42 03 39 09\n'
          '08 10 f3 ef 6f 00 47 c8 17 91 d7 54 36 c8 a6 08\n'
          '45',
        );
        expect(
          hexFromBytes(output),
          hexFromBytes(expected),
        );
      });
    });

    test('computeBlock(...)', () {
      final output = Uint32List(256);
      final input0 = Uint32List(256);
      final input1 = Uint32List(256);
      for (var i = 0; i < 256; i += 2) {
        input0[i] = i ~/ 2;
        input1[i] = 1 + i ~/ 2;
      }
      final state = DartArgon2State(
        mode: DartArgon2Mode.argon2id,
        parallelism: 1,
        memory: 8,
        iterations: 1,
        hashLength: 64,
      );
      state.processBlock(
        output: output,
        input0: input0,
        input1: input1,
        isXorred: false,
      );
      expect(
        output.take(16).toList(),
        [
          2303917630,
          1573244821,
          2052837629,
          1164931113,
          904650568,
          3265679110,
          1884721238,
          3414895650,
          102194870,
          3453617306,
          417647442,
          3480357198,
          2456541324,
          3124731797,
          1715126410,
          4169524563,
        ],
      );
    });

    test('getReferenceBlockIndexFromJ(...)', () {
      final expectedList = [
        // Current lane is always 0 (total 16 blocks).
        // Columns are (reference_lane, random_input) combinations.
        //
        // memory=24
        // iteration=0
        0, 0, 0, 0, 0, 8, 8, 8, 8, 8, // slice=1 index=0
        1, 1, 1, 0, 0, 9, 9, 9, 8, 8, // slice=1 index=1
        2, 1, 1, 0, 0, 10, 9, 9, 8, 8, // slice=2 index=0
        3, 2, 2, 0, 0, 11, 10, 10, 8, 8, // slice=2 index=1
        4, 2, 2, 0, 0, 12, 10, 10, 8, 8, // slice=3 index=0
        5, 3, 3, 0, 0, 13, 11, 11, 8, 8, // slice=3 index=1
        // iteration=1
        6, 4, 4, 2, 2, 14, 12, 12, 10, 10, // slice=0 index=0
        7, 5, 5, 2, 2, 15, 13, 13, 10, 10, // slice=0 index=1
        0, 6, 6, 4, 4, 8, 14, 14, 12, 12, // slice=1 index=0
        1, 7, 7, 4, 4, 9, 15, 15, 12, 12, // slice=1 index=1
        2, 0, 0, 6, 6, 10, 8, 8, 14, 14, // slice=2 index=0
        3, 1, 1, 6, 6, 11, 9, 9, 14, 14, // slice=2 index=1
        4, 2, 2, 0, 0, 12, 10, 10, 8, 8, // slice=3 index=0
        5, 3, 3, 0, 0, 13, 11, 11, 8, 8, // slice=3 index=1
        // memory=48
        // iteration=0
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // slice=0 index=2
        2, 1, 1, 0, 0, 18, 17, 17, 16, 16, // slice=1 index=0
        3, 2, 2, 0, 0, 19, 18, 18, 16, 16, // slice=1 index=1
        4, 2, 2, 0, 0, 19, 18, 18, 16, 16, // slice=1 index=2
        6, 3, 3, 0, 0, 22, 19, 19, 16, 16, // slice=2 index=0
        7, 4, 4, 0, 0, 23, 20, 20, 16, 16, // slice=2 index=1
        8, 4, 4, 1, 0, 23, 20, 20, 16, 16, // slice=2 index=2
        10, 6, 5, 1, 0, 26, 22, 21, 17, 16, // slice=3 index=0
        11, 6, 6, 1, 0, 27, 22, 22, 17, 16, // slice=3 index=1
        12, 7, 6, 1, 0, 27, 22, 22, 17, 16, // slice=3 index=2
        // iteration=1
        14, 10, 9, 5, 4, 30, 26, 25, 21, 20, // slice=0 index=0
        15, 10, 10, 5, 4, 31, 26, 26, 21, 20, // slice=0 index=1
        0, 11, 10, 5, 4, 31, 26, 26, 21, 20, // slice=0 index=2
        2, 14, 13, 9, 8, 18, 30, 29, 25, 24, // slice=1 index=0
        3, 14, 14, 9, 8, 19, 30, 30, 25, 24, // slice=1 index=1
        4, 15, 14, 9, 8, 19, 30, 30, 25, 24, // slice=1 index=2
        6, 2, 1, 13, 12, 22, 18, 17, 29, 28, // slice=2 index=0
        7, 2, 2, 13, 12, 23, 18, 18, 29, 28, // slice=2 index=1
        8, 3, 2, 13, 12, 23, 18, 18, 29, 28, // slice=2 index=2
        10, 6, 5, 1, 0, 26, 22, 21, 17, 16, // slice=3 index=0
        11, 6, 6, 1, 0, 27, 22, 22, 17, 16, // slice=3 index=1
        12, 7, 6, 1, 0, 27, 22, 22, 17, 16, // slice=3 index=2
      ];
      final parallelism = 3;
      var i = 0;
      for (var memory in [8 * parallelism, 16 * parallelism]) {
        final algorithm = DartArgon2State(
          mode: DartArgon2Mode.argon2id,
          parallelism: parallelism,
          memory: memory,
          iterations: 2,
          hashLength: 64,
        );
        final blocksPerSegment = memory ~/ parallelism ~/ 4;
        for (var iteration in [0, 1]) {
          for (var slice in [0, 1, 2, 3]) {
            for (var index in [0, 1, 2]) {
              if (index >= blocksPerSegment) {
                continue;
              }
              if (iteration == 0 && slice == 0 && index < 2) {
                continue;
              }
              for (var j2 in [0, 1]) {
                for (var j1 in [
                  0,
                  0xAABBCCDD,
                  0xB0B0B0B0,
                  0xF0F0F0F0,
                  0xFFFFFFFF,
                ]) {
                  final (referenceLane, referenceBlock) =
                      algorithm.referredBlockIndex(
                    iteration: iteration,
                    slice: slice,
                    lane: 0,
                    index: index,
                    j1: j1,
                    j2: j2,
                  );
                  if (iteration == 0 && slice == 0) {
                    expect(referenceLane, 0);
                  } else {
                    expect(referenceLane, j2);
                  }
                  final blocksPerLane =
                      algorithm.blockCount ~/ algorithm.parallelism;
                  final actual = referenceLane * blocksPerLane + referenceBlock;
                  final expected = expectedList[i];
                  i++;
                  const colN = 10;
                  expect(actual, expected,
                      reason: 'row=${i ~/ colN} col=${i % colN} memory=$memory,'
                          ' blocksPerLane=$blocksPerLane iteration=$iteration,'
                          ' slice=$slice, index=$index,'
                          ' j2 (reference lane)=$j2, j1=${j1.toRadixString(16)},');
                }
              }
            }
          }
        }
      }
    });

    group('gb', () {
      final algorithm = DartArgon2State(
        memory: 8,
        parallelism: 1,
        iterations: 1,
        hashLength: 32,
        mode: DartArgon2Mode.argon2id,
      );

      test('all 0', () {
        final data = Uint32List.fromList(
          [0, 0, 0, 0, 0, 0, 0, 0],
        );
        algorithm.gb(data, 0, 2, 4, 6);
        expect(
          data,
          [0, 0, 0, 0, 0, 0, 0, 0],
        );
      });

      test('all 1', () {
        const mask32 = 0xFFFFFFFF;
        final data = Uint32List.fromList(
          [
            mask32,
            mask32,
            mask32,
            mask32,
            mask32,
            mask32,
            mask32,
            mask32,
          ],
        );
        algorithm.gb(data, 0, 2, 4, 6);
        expect(
          data,
          [
            4294966016,
            1019,
            3360028167,
            3860592649,
            467468291,
            4077780987,
            4228186111,
            4211343359
          ],
        );
      });

      test('a=1', () {
        final data = Uint32List.fromList(
          [1, 0, 0, 0, 0, 0, 0, 0],
        );
        algorithm.gb(data, 0, 2, 4, 6);
        expect(
          data,
          [
            769,
            0,
            131584,
            100794370,
            65536,
            50397185,
            65536,
            50397184,
          ],
        );
      });

      test('b=1', () {
        final data = Uint32List.fromList(
          [0, 0, 1, 0, 0, 0, 0, 0],
        );
        algorithm.gb(data, 0, 2, 4, 6);
        expect(
          data,
          [
            769,
            256,
            33686016,
            100794882,
            16842752,
            50397185,
            16842752,
            50397184,
          ],
        );
      });

      test('c=1', () {
        final data = Uint32List.fromList(
          [0, 0, 0, 0, 1, 0, 0, 0],
        );
        algorithm.gb(data, 0, 2, 4, 6);
        expect(
          data,
          [
            0,
            256,
            100663298,
            512,
            50331649,
            0,
            16777216,
            0,
          ],
        );
      });

      test('d=1', () {
        final data = Uint32List.fromList(
          [0, 0, 0, 0, 0, 0, 1, 0],
        );
        algorithm.gb(data, 0, 2, 4, 6);
        expect(
          data,
          [
            256,
            0,
            131584,
            33554434,
            65536,
            16777217,
            65536,
            16777216,
          ],
        );
      });

      test('example #1', () {
        final data = Uint32List.fromList(
          [12, 34, 56, 78, 90, 12, 34, 56],
        );
        algorithm.gb(data, 0, 2, 4, 6);
        expect(
          data,
          [
            1107943812,
            3373680,
            2437666783,
            3288237613,
            3365935087,
            3788257558,
            2144748041,
            3788242995,
          ],
        );
      });
    });
  });
}
