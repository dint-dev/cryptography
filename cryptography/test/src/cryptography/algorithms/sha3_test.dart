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

import 'package:crypto/crypto.dart' as google_crypto;
import 'package:cryptography/cryptography.dart';
import 'package:cryptography/utils.dart';
import 'package:test/test.dart';

void main() {
  group('sha3V224', () {
    const algorithm = sha3V224;

    test('example #1', () {
      final message = hexToBytes(
        '',
      );
      final expectedHash = hexToBytes(
        '6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7',
      );
      expect(
        hexFromBytes(algorithm.hashSync(message).bytes),
        hexFromBytes(expectedHash),
      );
    });
  });

  group('sha3V256', () {
    const algorithm = sha3V256;

    test('example #1', () {
      final message = hexToBytes(
        '',
      );
      final expectedHash = hexToBytes(
        'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a',
      );
      expect(
        hexFromBytes(algorithm.hashSync(message).bytes),
        hexFromBytes(expectedHash),
      );
    });
  });

  group('sha3V384', () {
    const algorithm = sha3V384;

    test('example #1', () {
      final message = hexToBytes(
        '',
      );
      final expectedHash = hexToBytes(
        '0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004',
      );
      expect(
        hexFromBytes(algorithm.hashSync(message).bytes),
        hexFromBytes(expectedHash),
      );
    });
  });

  group('sha3V512', () {
    const algorithm = sha3V512;

    test('example #1', () {
      final message = hexToBytes(
        '',
      );
      final expectedHash = hexToBytes(
        'a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26',
      );
      expect(
        hexFromBytes(algorithm.hashSync(message).bytes),
        hexFromBytes(expectedHash),
      );
    });
  });
}
