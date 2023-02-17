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

import '_helpers.dart';
import 'base_classes.dart';
import 'blake2b.dart';

class Blake2bSink extends DartHashSink {
  static const List<int> _initializationVector = <int>[
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
  ];
  static const int _uint64mask = 0xFFFFFFFFFFFFFFFF;
  final _hash = Uint64List(16);
  final _bufferAsUint64List = Uint64List(16);
  Uint8List? _bufferAsBytes;
  int _length = 0;
  Hash? _result;

  bool _isClosed = false;

  final _localValues = Uint64List(16);

  Blake2bSink() {
    checkSystemIsLittleEndian();

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
      bufferAsBytes = Uint8List.view(_bufferAsUint64List.buffer);
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

    // Return bytes
    final resultBytes = Uint8List(64);
    resultBytes.setAll(
      0,
      Uint8List.view(_hash.buffer, 0, 64),
    );
    _result = Hash(UnmodifiableUint8ListView(resultBytes));
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
    final m = _bufferAsUint64List;

    // Initialize v[0..7]
    for (var i = 0; i < 8; i++) {
      v[i] = h[i];
    }

    // Initialize v[8..15]
    for (var i = 0; i < 8; i++) {
      v[8 + i] = _initializationVector[i];
    }

    // Set length.
    final length = _length;
    v[12] ^= length;
    v[13] ^= 0;

    // Is this the last block?
    if (isLast) {
      v[14] ^= _uint64mask;
    }

    final sigma = sigmaConstants;
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
    for (var i = 0; i < 8; i++) {
      h[i] ^= v[i] ^ v[8 + i];
    }
  }

  /// Exported so this can be used by both:
  ///   * [DartBlake2b]
  ///   * [DartArgon2id]
  static void g(
    Uint64List v,
    int a,
    int b,
    int c,
    int d,
    Uint64List m,
    int x,
    int y,
  ) {
    var va = v[a];
    var vb = v[b];
    var vc = v[c];
    var vd = v[d];
    va += vb + m[x];
    {
      // vd = rotateRight(vd ^ va, 32)
      final arg = vd ^ va;
      const n = 32;
      vd = ((~(1 << 63) & arg) >> n) |
          (arg << (64 - n)) |
          (arg.isNegative ? (1 << (63 - n)) : 0);
    }
    vc += vd;
    {
      // vb = rotateRight(vb ^ vc, 24)
      final rotated = vb ^ vc;
      const n = 24;
      vb = ((~(1 << 63) & rotated) >> n) |
          (rotated << (64 - n)) |
          (rotated.isNegative ? (1 << (63 - n)) : 0);
    }
    va += vb + m[y];
    {
      // vd = rotateRight(vd ^ va, 16)
      final arg = vd ^ va;
      const n = 16;
      vd = ((~(1 << 63) & arg) >> n) |
          (arg << (64 - n)) |
          (arg.isNegative ? (1 << (63 - n)) : 0);
    }
    vc += vd;
    {
      // vb = rotateRight(vb ^ vc, 63)
      final rotated = vb ^ vc;
      vb = (rotated << 1) | (rotated.isNegative ? 1 : 0);
    }
    v[a] = va;
    v[b] = vb;
    v[c] = vc;
    v[d] = vd;
  }
}
