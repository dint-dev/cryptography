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

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/src/utils.dart';
import 'package:meta/meta.dart';

import 'base_classes.dart';
import 'blake2b.dart';

class Blake2bSink extends DartHashSink {
  static const List<int> _initializationVector = <int>[
    // 0
    0xF3BCC908,
    0x6A09E667,
    // 1
    0x84CAA73B,
    0xBB67AE85,
    // 2
    0xFE94F82B,
    0x3C6EF372,
    // 3
    0x5F1D36F1,
    0xA54FF53A,
    // 4
    0xADE682D1,
    0x510E527F,
    // 5
    0x2B3E6C1F,
    0x9B05688C,
    // 6
    0xFB41BD6B,
    0x1F83D9AB,
    // 7
    0x137E2179,
    0x5BE0CD19,
  ];
  final Uint32List _hash = Uint32List(32);
  final Uint32List _bufferAsUint32List = Uint32List(32);
  Uint8List? _bufferAsBytes;
  int _length = 0;
  Hash? _result;
  bool _isClosed = false;
  final Uint32List _localValues = Uint32List(32);

  Blake2bSink() {
    // Only implemented for Little Endian CPUs
    if (Endian.host != Endian.little) {
      throw UnimplementedError();
    }

    final h = _hash;
    h.setAll(0, _initializationVector);
    h[0] ^= 0x01010000 ^ 64;
  }

  @override
  void addSlice(List<int> chunk, int start, int end, bool isLast) {
    if (_isClosed) {
      throw StateError('Already closed');
    }

    var bufferAsBytes = _bufferAsBytes;
    if (bufferAsBytes == null) {
      bufferAsBytes ??= Uint8List.view(_bufferAsUint32List.buffer);
      _bufferAsBytes = bufferAsBytes;
    }
    var length = _length;
    for (var i = start; i < end; i++) {
      final bufferIndex = length % 64;

      // If first byte of a new block
      if (bufferIndex == 0 && length > 0) {
        // Store length
        _length = length;

        // Compress the previous block
        _compress(false);
      }

      // Set byte
      bufferAsBytes[bufferIndex] = chunk[i];

      // Increment length
      length++;
    }

    // Store length
    _length = length;

    if (isLast) {
      close();
    }
  }

  @override
  void close() {
    if (_isClosed) {
      return;
    }
    _isClosed = true;

    final length = _length;

    // Fill remaining indices with zeroes
    final blockLength = length % 64;
    if (blockLength > 0) {
      _bufferAsBytes!.fillRange(blockLength, 64, 0);
    }

    // Compress
    _compress(true);

    // Change:
    // Host endian --> little endian
    final hash = _hash;

    // Return bytes
    _result = Hash(List<int>.unmodifiable(
      Uint8List.view(
        hash.buffer,
        hash.offsetInBytes,
        64,
      ),
    ));
  }

  @override
  Hash hashSync() {
    final result = _result;
    if (result == null) {
      throw StateError('Not closed');
    }
    return result;
  }

  void _compress(bool isLast) {
    final h = _hash;
    final v = _localValues;
    final m = _bufferAsUint32List;

    // Initialize v[0..15]
    for (var i = 0; i < 16; i++) {
      v[i] = h[i];
    }

    // Initialize v[16..32]
    final initializationVector = _initializationVector;
    for (var i = 0; i < 16; i++) {
      v[16 + i] = initializationVector[i];
    }

    // Set length.
    // We can't use setUint64(...) because it doesn't work in browsers.
    final length = _length;
    v[24] ^= uint32mask & length;
    v[25] ^= uint32mask & (length ~/ (uint32mask + 1));
    v[26] ^= 0;
    v[27] ^= 0;

    // Is this the last block?
    if (isLast) {
      v[28] ^= uint32mask;
      v[29] ^= uint32mask;
    }

    final sigma = sigmaConstants;

    // 12 rounds
    for (var round = 0; round < 12; round++) {
      // Sigma index
      final si = round * 16;

      g(v, 0, 4, 8, 12, m, sigma[si + 0], sigma[si + 1]);
      g(v, 1, 5, 9, 13, m, sigma[si + 2], sigma[si + 3]);
      g(v, 2, 6, 10, 14, m, sigma[si + 4], sigma[si + 5]);
      g(v, 3, 7, 11, 15, m, sigma[si + 6], sigma[si + 7]);

      g(v, 0, 5, 10, 15, m, sigma[si + 8], sigma[si + 9]);
      g(v, 1, 6, 11, 12, m, sigma[si + 10], sigma[si + 11]);
      g(v, 2, 7, 8, 13, m, sigma[si + 12], sigma[si + 13]);
      g(v, 3, 4, 9, 14, m, sigma[si + 14], sigma[si + 15]);
    }

    // Copy.
    for (var i = 0; i < 16; i++) {
      h[i] = h[i] ^ v[i] ^ v[16 + i];
    }
  }

  /// Used by this file and Argon2.
  @visibleForTesting
  static void g(
    Uint32List v,
    int a,
    int b,
    int c,
    int d,
    List<int> m,
    int x,
    int y,
  ) {
    a *= 2;
    b *= 2;
    c *= 2;
    d *= 2;
    x *= 2;
    y *= 2;
    sum(v, a, b, m as Uint32List?, x);
    xorAndRotate(v, d, a, 32);
    sum(v, c, d, null, null);
    xorAndRotate(v, b, c, 24);
    sum(v, a, b, m as Uint32List?, y);
    xorAndRotate(v, d, a, 16);
    sum(v, c, d, null, null);
    xorAndRotate(v, b, c, 63);
  }

  @visibleForTesting
  static void sum(Uint32List v, int a, int b, Uint32List? m, int? x) {
    var mxLow = 0;
    var mxHigh = 0;
    if (m != null) {
      mxLow = m[x!];
      mxHigh = m[x + 1];
    }
    var low = v[a] + v[b] + mxLow;
    var high = v[a + 1] + v[b + 1] + mxHigh;

    // Carry
    high += low ~/ (uint32mask + 1);

    v[a] = uint32mask & low;
    v[a + 1] = uint32mask & high;
  }

  @visibleForTesting
  static void xorAndRotate(Uint32List v, int a, int b, int n) {
    final low = v[a] ^ v[b];
    final high = v[a + 1] ^ v[b + 1];
    if (n < 32) {
      v[a] = (uint32mask & (high << (32 - n))) | (low >> n);
      v[a + 1] = (uint32mask & (low << (32 - n))) | (high >> n);
    } else if (n == 32) {
      v[a] = high;
      v[a + 1] = low;
    } else if (n == 63) {
      v[a] = (uint32mask & (low << 1)) | (high >> 31);
      v[a + 1] = (uint32mask & (high << 1)) | (low >> 31);
    } else {
      throw ArgumentError.value(n, 'n');
    }
  }
}
