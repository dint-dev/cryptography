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

import 'dart:typed_data';

import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:test/test.dart';

void main() {
  group('PaddingAlgorithm.zero with blockLength=4:', () {
    final algorithm = PaddingAlgorithm.zero;

    test('blockLength must be 2 or greater', () {
      expect(
        () => algorithm.setBlockPadding(1, Uint8List.fromList([0, 0, 0, 0]), 0),
        throwsArgumentError,
      );
      algorithm.setBlockPadding(2, Uint8List.fromList([0, 0, 0, 0]), 0);
      expect(
        () => algorithm.getBlockPadding(1, Uint8List.fromList([0, 0, 0, 0])),
        throwsArgumentError,
      );
      expect(
        algorithm.getBlockPadding(2, Uint8List.fromList([0, 0, 0, 0])),
        0,
      );
    });

    group('setBlockPadding(...) when blockLength=4:', () {
      test('input length = 0', () {
        final bytes = Uint8List(0);
        algorithm.setBlockPadding(4, bytes, 0);
      });
      test('dataLength = 1', () {
        final bytes = Uint8List.fromList([100, 0, 0, 0]);
        algorithm.setBlockPadding(4, bytes, 1);
        expect(bytes, [100, 0, 0, 0]);
      });
      test('dataLength = 4', () {
        final bytes = Uint8List.fromList([100, 101, 102, 103]);
        algorithm.setBlockPadding(4, bytes, 4);
        expect(bytes, [100, 101, 102, 103]);
      });
    });
  });
  group('PaddingAlgorithm.pkcs7 with blockLength=4:', () {
    final algorithm = PaddingAlgorithm.pkcs7;

    test('toString()', () {
      expect(algorithm.toString(), 'PaddingAlgorithm.pkcs7');
    });

    group('paddingLength(...)', () {
      test('throws when blockLength=1', () {
        expect(() => algorithm.paddingLength(1, 0), throwsArgumentError);
      });
      test('throws when blockLength=0x100', () {
        expect(() => algorithm.paddingLength(0x100, 0), throwsArgumentError);
      });
      test('throws when dataLength=-1', () {
        expect(() => algorithm.paddingLength(4, -1), throwsArgumentError);
      });
      test('paddingLength', () {
        expect(() => algorithm.paddingLength(1, 0), throwsArgumentError);
        expect(() => algorithm.paddingLength(0x100, 0), throwsArgumentError);
        expect(() => algorithm.paddingLength(4, -1), throwsArgumentError);
        expect(algorithm.paddingLength(4, 0), 4);
        expect(algorithm.paddingLength(4, 1), 3);
        expect(algorithm.paddingLength(4, 2), 2);
        expect(algorithm.paddingLength(4, 3), 1);
        expect(algorithm.paddingLength(4, 4), 4);
        expect(algorithm.paddingLength(4, 5), 3);
        expect(algorithm.paddingLength(4, 6), 2);
        expect(algorithm.paddingLength(4, 7), 1);
        expect(algorithm.paddingLength(4, 8), 4);
      });
    });

    group('setBlockPadding', () {
      test('bytes length=0', () {
        final bytes = Uint8List.fromList([]);
        expect(
          () => algorithm.setBlockPadding(4, bytes, 0),
          throwsArgumentError,
        );
      });
      test('bytes length=3', () {
        final bytes = Uint8List.fromList([0, 0, 0]);
        expect(
          () => algorithm.setBlockPadding(4, bytes, 0),
          throwsArgumentError,
        );
        expect(bytes, [0, 0, 0]);
      });
      test('dataLength=0', () {
        final bytes = Uint8List.fromList([0, 0, 0, 0]);
        algorithm.setBlockPadding(4, bytes, 0);
        expect(bytes, [4, 4, 4, 4]);
      });
      test('dataLength=1', () {
        final bytes = Uint8List.fromList([100, 0, 0, 0]);
        bytes[0] = 100;
        algorithm.setBlockPadding(4, bytes, 1);
        expect(bytes, [100, 3, 3, 3]);
      });
      test('dataLength=2', () {
        final bytes = Uint8List.fromList([100, 101, 0, 0]);
        algorithm.setBlockPadding(4, bytes, 2);
        expect(bytes, [100, 101, 2, 2]);
      });
      test('dataLength=3', () {
        final bytes = Uint8List.fromList([100, 101, 102, 0]);
        algorithm.setBlockPadding(4, bytes, 3);
        expect(bytes, [100, 101, 102, 1]);
      });
      test('dataLength=4', () {
        final bytes = Uint8List.fromList([100, 101, 102, 103]);
        expect(
          () => algorithm.setBlockPadding(4, bytes, 4),
          throwsArgumentError,
        );
        expect(bytes, [100, 101, 102, 103]);
      });
    });
    group('getBlockPadding', () {
      test('returns 1', () {
        expect(
          algorithm.getBlockPadding(4, Uint8List.fromList([0, 0, 0, 1])),
          1,
        );
        expect(
          algorithm.getBlockPadding(4, Uint8List.fromList([1, 1, 1, 1])),
          1,
        );
      });
      test('returns 2', () {
        expect(
          algorithm.getBlockPadding(4, Uint8List.fromList([0, 0, 2, 2])),
          2,
        );
      });
      test('returns 3', () {
        expect(
          algorithm.getBlockPadding(4, Uint8List.fromList([0, 3, 3, 3])),
          3,
        );
      });
      test('returns 4', () {
        expect(
          algorithm.getBlockPadding(
            4,
            Uint8List.fromList([4, 4, 4, 4]),
          ),
          4,
        );
        expect(
          algorithm.getBlockPadding(
            4,
            Uint8List.fromList([4, 4, 4, 4, 4, 4, 4, 4]),
          ),
          4,
        );
      });
      test('returns -1 if bytes is not block length aligned', () {
        expect(
          algorithm.getBlockPadding(4, Uint8List(0)),
          -1,
        );
        expect(
          algorithm.getBlockPadding(4, Uint8List(3)),
          -1,
        );
        expect(
          algorithm.getBlockPadding(4, Uint8List(5)),
          -1,
        );
      });
      test('returns -1 if larger than block length', () {
        expect(
          algorithm.getBlockPadding(
            4,
            Uint8List.fromList([5, 5, 5, 5]),
          ),
          -1,
        );
        expect(
          algorithm.getBlockPadding(
            4,
            Uint8List.fromList([5, 5, 5, 5, 5]),
          ),
          -1,
        );
        expect(
          algorithm.getBlockPadding(
            4,
            Uint8List.fromList([
              5, 5, 5, 5, //
              5, 5, 5, 5,
            ]),
          ),
          -1,
        );
      });
    });
  });

  group('RsaPublicKey:', () {
    test('"==" / hashCode', () {
      final value = RsaPublicKey(
        e: [1],
        n: [2],
      );
      final clone = RsaPublicKey(
        e: [1],
        n: [2],
      );
      final other0 = RsaPublicKey(
        e: [9999],
        n: [2],
      );
      final other1 = RsaPublicKey(
        e: [1],
        n: [9999],
      );

      expect(value, clone);
      expect(value, isNot(other0));
      expect(value, isNot(other1));

      expect(value.hashCode, clone.hashCode);
      expect(value.hashCode, isNot(other0.hashCode));
      expect(value.hashCode, isNot(other1.hashCode));
    });

    test('toString() does not expose actual bytes', () {
      final value = RsaPublicKey(
        e: [1],
        n: [2, 3, 4, 5],
      );
      expect(
          value.toString(), 'RsaPublicKey(\n  e: [1],\n  n: [..., 4, 5],\n)');
    });
  });
}
