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
  group('Argon2id:', () {
    _main();
  });
}

void _main() {
  late Argon2id algorithm;
  setUp(() {
    algorithm = Argon2id(
      parallelism: 3,
      memorySize: 32 * 1024,
      iterations: 3,
      hashLength: 32,
    );
  });

  test('Throws UnimplementedError', () async {
    final future = algorithm.deriveKey(
      secretKey: SecretKey(List<int>.filled(32, 0x1)),
      nonce: List<int>.filled(16, 0x2),
      k: List<int>.filled(8, 0x3),
      ad: List<int>.filled(12, 0x4),
    );
    await expectLater(future, throwsUnimplementedError);
  });

  // test('test vector from RFC 7693', () async {
  //   final actual = await algorithm.deriveKey(
  //     SecretKeyData(List<int>.filled(32, 0x1), type: SecretKeyType.unspecified),
  //     salt: List<int>.filled(16, 0x2),
  //     key: List<int>.filled(8, 0x3),
  //     ad: List<int>.filled(12, 0x4),
  //   );
  //
  //   final expected = hexToBytes(
  //     '51 2b 39 1b 6f 11 62 97'
  //     '53 71 d3 09 19 73 42 94'
  //     'f8 68 e3 be 39 84 f3 c1'
  //     'a1 3a 4d b9 fa be 4a cb',
  //   );
  //
  //   expect(
  //     hexFromBytes((await actual.extract()).bytes),
  //     hexFromBytes(expected),
  //   );
  // });
}
