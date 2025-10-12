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

import 'package:cryptography_plus/dart.dart';
import 'package:meta/meta.dart';

import '../../cryptography_plus.dart';
import '../_internal/rotate.dart';

/// A pure Dart implementation of [Sha224].
///
/// For examples and more information about the algorithm, see documentation for
/// the class [Sha224].
class DartSha224 extends Sha224 with DartHashAlgorithmMixin {
  static const _initialValues = [
    0xc1059ed8,
    0x367cd507,
    0x3070dd17,
    0xf70e5939,
    0xffc00b31,
    0x68581511,
    0x64f98fa7,
    0xbefa4fa4,
  ];

  const DartSha224() : super.constructor();

  @override
  DartHashSink newHashSink() {
    return _DartSha256BasedState(28, _initialValues);
  }
}

/// A pure Dart implementation of [Sha256].
///
/// For examples and more information about the algorithm, see documentation for
/// the class [Sha256].
class DartSha256 extends Sha256 with DartHashAlgorithmMixin {
  static const _initialValues = [
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19,
  ];

  @literal
  const DartSha256() : super.constructor();

  @override
  DartHashSink newHashSink() {
    return _DartSha256BasedState(32, _initialValues);
  }
}

class _DartSha256BasedState extends DartHashSink implements HashSink {
  static const _noise = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, //
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

  final List<int> _initialValues;

  /// The sixteen words from the original chunk, extended to 64 words.
  ///
  /// This is an instance variable to avoid re-allocating, but its data isn't
  /// used across invocations of [updateHash].
  final _buffer = ByteData(64);
  late final Uint32List _bufferAsUint32List = Uint32List.view(_buffer.buffer);
  final Uint32List _w = Uint32List(64);
  final Uint32List _digest;
  bool _isClosed = false;
  var _bufferIndex = 0;
  int _length = 0;

  @override
  final Uint8List hashBytes;

  factory _DartSha256BasedState(int digestLength, List<int> initialValues) {
    final digest = Uint32List(8);
    final digestView = Uint8List.view(digest.buffer, 0, digestLength);
    return _DartSha256BasedState._(digest, digestView, initialValues);
  }

  _DartSha256BasedState._(this._digest, this.hashBytes, this._initialValues) {
    reset();
  }

  @override
  bool get isClosed => _isClosed;

  @override
  int get length => _length;

  @override
  void add(List<int> chunk) {
    addSlice(chunk, 0, chunk.length, false);
  }

  @override
  void addSlice(List<int> chunk, int start, int end, bool isLast) {
    if (isClosed) {
      throw StateError('The sink has been closed');
    }
    _addSlice(chunk, start, end);
    if (isLast) {
      _isClosed = true;

      // Append zeroes until state index is right
      final buffer = _buffer;
      var i = _bufferIndex;
      buffer.setUint8(i, 0x80);
      i++;
      if (i > 56) {
        for (; i < 64; i++) {
          buffer.setUint8(i, 0);
        }
        _processBlock();
        i = 0;
      }
      for (; i < 56; i++) {
        buffer.setUint8(i, 0);
      }
      final lengthInBits = 8 * _length;
      buffer.setUint32(
        56,
        lengthInBits ~/ (uint32mask + 1),
        Endian.big,
      );
      buffer.setUint32(
        60,
        lengthInBits % (uint32mask + 1),
        Endian.big,
      );

      _processBlock();

      final digest = _digest;
      if (Endian.host != Endian.big) {
        // Switch endian
        for (var i = 0; i < 8; i++) {
          final v = digest[i];
          digest[i] = ((0xFF & v) << 24) |
              (0xFF0000 & (v << 8)) |
              (0xFF00 & (v >> 8)) |
              (v >> 24);
        }
      }
    }
  }

  @override
  void close() {
    if (!isClosed) {
      addSlice(const [], 0, 0, true);
    }
  }

  @override
  void reset() {
    _bufferIndex = 0;
    _length = 0;
    _isClosed = false;
    final digest = _digest;
    final initialValues = _initialValues;
    for (var i = 0; i < digest.length; i++) {
      digest[i] = initialValues[i];
    }
  }

  void _addSlice(List<int> chunk, int start, int end) {
    RangeError.checkValidRange(start, end, chunk.length);
    final rangeLength = end - start;
    if (rangeLength == 0) {
      return;
    }
    _length += rangeLength;
    final buffer = _buffer;
    var bufferIndex = _bufferIndex;
    for (; start < end; start++) {
      buffer.setUint8(bufferIndex, chunk[start]);
      bufferIndex++;
      if (bufferIndex == 64) {
        _processBlock();
        bufferIndex = 0;
      }
    }
    _bufferIndex = bufferIndex;
  }

  void _processBlock() {
    final w = _w;
    final buffer = _bufferAsUint32List;
    for (var i = 0; i < 16; i++) {
      final v = buffer[i];
      w[i] = ((0xFF & v) << 24) |
          (0xFF0000 & (v << 8)) |
          (0xFF00 & (v >> 8)) |
          (v >> 24);
    }
    for (var i = 16; i < 64; i++) {
      final w2 = w[i - 2];
      final w7 = w[i - 7];
      final w15 = w[i - 15];
      final w16 = w[i - 16];
      final s0a = (uint32mask & (w15 << (32 - 7))) | (w15 >> 7);
      final s0b = (uint32mask & (w15 << (32 - 18))) | (w15 >> 18);
      final s0 = s0a ^ s0b ^ (w15 >> 3);
      final s1a = (uint32mask & (w2 << (32 - 17))) | (w2 >> 17);
      final s1b = (uint32mask & (w2 << (32 - 19))) | (w2 >> 19);
      final s1 = s1a ^ s1b ^ (w2 >> 10);
      w[i] = w16 + s0 + w7 + s1;
    }

    // Shuffle around the bits.
    final digest = _digest;
    var a = digest[0];
    var b = digest[1];
    var c = digest[2];
    var d = digest[3];
    var e = digest[4];
    var f = digest[5];
    var g = digest[6];
    var h = digest[7];

    final noise = _noise;
    for (var i = 0; i < 64; i++) {
      final s1a = (uint32mask & (e << (32 - 6))) | (e >> 6);
      final s1b = (uint32mask & (e << (32 - 11))) | (e >> 11);
      final s1c = (uint32mask & (e << (32 - 25))) | (e >> 25);
      final s1 = s1a ^ s1b ^ s1c;
      final ch = (e & f) ^ ((uint32mask ^ e) & g);
      final temp1 = uint32mask & (h + s1 + ch + noise[i] + w[i]);

      final s0a = (uint32mask & (a << (32 - 2))) | (a >> 2);
      final s0b = (uint32mask & (a << (32 - 13))) | (a >> 13);
      final s0c = (uint32mask & (a << (32 - 22))) | (a >> 22);
      final s0 = s0a ^ s0b ^ s0c;
      final maj = (a & b) ^ (a & c) ^ (b & c);
      final temp2 = uint32mask & (s0 + maj);

      h = g;
      g = f;
      f = e;
      e = uint32mask & (d + temp1);
      d = c;
      c = b;
      b = a;
      a = uint32mask & (temp1 + temp2);
    }

    // Update hash values after iteration.
    digest[0] = a + digest[0];
    digest[1] = b + digest[1];
    digest[2] = c + digest[2];
    digest[3] = d + digest[3];
    digest[4] = e + digest[4];
    digest[5] = f + digest[5];
    digest[6] = g + digest[6];
    digest[7] = h + digest[7];
  }
}
