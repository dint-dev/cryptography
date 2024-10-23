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

import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:test/test.dart';

import '../hex.dart';

void testArgon2() {
  group('$Argon2id:', () {
    test('memory=1MB parallelism=1 iterations=1', () async {
      final algorithm = Argon2id(
        memory: 1000,
        parallelism: 1,
        iterations: 1,
        hashLength: 32,
      );

      final result = await (await algorithm.deriveKey(
        secretKey: SecretKey(utf8.encode('password')),
        nonce: utf8.encode('nonce'),
        optionalSecret: utf8.encode("secret"),
        associatedData: utf8.encode("data"),
      ))
          .extractBytes();

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
      final algorithm = Argon2id(
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
      final algorithm = Argon2id(
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
      final algorithm = Argon2id(
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
}
