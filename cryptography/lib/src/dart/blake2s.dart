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

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart';
import 'package:cryptography/src/dart/_helpers.dart';

import '../_internal/rotate.dart';

/// [Blake2s] implemented in pure Dart.
///
/// For examples and more information about the algorithm, see documentation for
/// the class [Blake2s].
class DartBlake2s extends Blake2s with DartHashAlgorithmMixin {
  const DartBlake2s() : super.constructor();

  @override
  DartHashSink newHashSink() {
    return _Blake2sSink();
  }
}

class _Blake2sSink extends DartHashSink {
  static const List<int> _initializationVector = <int>[
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19,
  ];

  static const List<int> _sigma = <int>[
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, // 16 bytes
    14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
    11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
    7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
    9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
    2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
    12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
    13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
    6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
    10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3
  ];

  final Uint32List _hash = Uint32List(16);
  final Uint32List _localValues = Uint32List(16);
  final Uint32List _buffer = Uint32List(16);
  int _length = 0;

  @override
  late final Uint8List hashBytes = Uint8List.view(
    _hash.buffer,
    0,
    32,
  );

  late final Uint8List _bufferAsBytes = Uint8List.view(_buffer.buffer);

  bool _isClosed = false;
  _Blake2sSink() {
    checkSystemIsLittleEndian();
    _initializeH(_hash);
  }
  @override
  bool get isClosed => _isClosed;

  @override
  int get length => _length;

  @override
  void addSlice(List<int> chunk, int start, int end, bool isLast) {
    if (isClosed) {
      throw StateError('Already closed');
    }

    final bufferAsBytes = _bufferAsBytes;
    var length = _length;
    for (var i = start; i < end; i++) {
      // Compress?
      if (length % 64 == 0 && length > 0) {
        _compress(
          _hash,
          _localValues,
          _buffer,
          length,
          false,
        );
      }

      // Set byte
      bufferAsBytes[length % 64] = chunk[i];

      // Increment length
      length++;
    }

    // Store length
    _length = length;

    if (isLast) {
      _isClosed = true;
      if (length == 0 || length % 64 != 0) {
        for (var i = length % 64; i < 64; i++) {
          bufferAsBytes[i] = 0;
        }
      }
      _compress(
        _hash,
        _localValues,
        _buffer,
        length,
        true,
      );
    }
  }

  @override
  void reset() {
    _length = 0;
    _isClosed = false;
    _buffer.fillRange(0, 16, 0);
    _localValues.fillRange(0, 16, 0);
    _initializeH(_hash);
  }

  /// Internal compression function.
  static void _compress(
    Uint32List h,
    Uint32List v,
    Uint32List m,
    int length,
    bool isLast,
  ) {
    // Initialize v[0..7]
    for (var i = 0; i < 8; i++) {
      v[i] = h[i];
    }

    // Initialize v[8..15]
    const initializationVector = _initializationVector;
    for (var i = 0; i < 8; i++) {
      v[8 + i] = initializationVector[i];
    }

    // Set length.
    // We can't use setUint64(...) because it doesn't work in browsers.
    v[12] ^= uint32mask & length;
    v[13] ^= length ~/ (uint32mask + 1);

    // Is this the last block?
    if (isLast) {
      v[14] ^= uint32mask;
    }

    const sigma = _sigma;

    // 10 rounds
    for (var round = 0; round < 10; round++) {
      // Sigma index
      final si = round * 16;

      _g(v, 0, 4, 8, 12, m[sigma[si + 0]], m[sigma[si + 1]]);
      _g(v, 1, 5, 9, 13, m[sigma[si + 2]], m[sigma[si + 3]]);
      _g(v, 2, 6, 10, 14, m[sigma[si + 4]], m[sigma[si + 5]]);
      _g(v, 3, 7, 11, 15, m[sigma[si + 6]], m[sigma[si + 7]]);

      _g(v, 0, 5, 10, 15, m[sigma[si + 8]], m[sigma[si + 9]]);
      _g(v, 1, 6, 11, 12, m[sigma[si + 10]], m[sigma[si + 11]]);
      _g(v, 2, 7, 8, 13, m[sigma[si + 12]], m[sigma[si + 13]]);
      _g(v, 3, 4, 9, 14, m[sigma[si + 14]], m[sigma[si + 15]]);
    }

    // Copy.
    for (var i = 0; i < 8; i++) {
      h[i] ^= v[i] ^ v[8 + i];
    }
  }

  static void _g(Uint32List v, int a, int b, int c, int d, int x, int y) {
    var va = v[a];
    var vb = v[b];
    var vc = v[c];
    var vd = v[d];

    {
      va = uint32mask & (va + vb + x);
      final rotated = vd ^ va;
      vd = (uint32mask & (rotated << 16)) | (rotated >> 16);
    }

    {
      vc = uint32mask & (vc + vd);
      final rotated = vb ^ vc;
      vb = (uint32mask & (rotated << 20)) | (rotated >> 12);
    }

    {
      va = uint32mask & (va + vb + y);
      final rotated = vd ^ va;
      vd = (uint32mask & (rotated << 24)) | (rotated >> 8);
    }

    {
      vc = uint32mask & (vc + vd);
      final rotated = vb ^ vc;
      vb = (uint32mask & (rotated << 25)) | (rotated >> 7);
    }

    v[a] = va;
    v[b] = vb;
    v[c] = vc;
    v[d] = vd;
  }

  /// Internal initialization function.
  static void _initializeH(Uint32List h) {
    h.setAll(0, _initializationVector);
    h[0] ^= 0x01010000 ^ 32;
  }
}
