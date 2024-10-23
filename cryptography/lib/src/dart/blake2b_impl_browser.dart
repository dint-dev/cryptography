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

import 'package:cryptography_plus/src/utils.dart';

import '../../cryptography_plus.dart';
import '../../dart.dart';
import '_helpers.dart';

/// Block size (in bytes).
const _blockSizeInBytes = 128;

/// Maximum key size (in bytes).
const _maxHashSizeInBytes = 64;

/// Maximum key size (in bytes).
const _maxKeySizeInBytes = 64;

class Blake2bSink extends DartHashSink with DartMacSinkMixin {
  /// Initialization vector.
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

  static const _bit32 = uint32mask + 1;

  /// Sigma values.
  static const _sigma = <int>[
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

  /// Hash: 16 x uint32
  final _hash = Uint32List(16);

  /// Hash: N bytes (N <= 32)
  @override
  late final Uint8List hashBytes = Uint8List.view(
    _hash.buffer,
    0,
    hashLengthInBytes,
  );

  /// Buffer for writing data: 32 x uint32
  final _bufferAsUint32List = Uint32List(32);

  /// Buffer for writing data: 64 bytes
  late final Uint8List _bufferAsBytes = Uint8List.view(
    _bufferAsUint32List.buffer,
  );

  /// Total length so far.
  int _length = 0;

  /// Whether [close] was called.
  bool _isClosed = false;

  /// State of the hash: 32 x uint32
  final _localValues = Uint32List(32);

  /// Hash length in bytes (constructor parameter).
  final int hashLengthInBytes;

  Blake2bSink({
    required this.hashLengthInBytes,
  }) {
    checkSystemIsLittleEndian();

    if (hashLengthInBytes < 1 || hashLengthInBytes > _maxHashSizeInBytes) {
      throw ArgumentError.value(hashLengthInBytes);
    }

    _initialize(key: null);
  }

  @override
  bool get isClosed => _isClosed;

  @override
  int get length => _length;

  @override
  Uint8List get macBytes => hashBytes;

  @override
  void addSlice(List<int> chunk, int start, int end, bool isLast) {
    if (isClosed) {
      throw StateError('Already closed');
    }

    final bufferAsBytes = _bufferAsBytes;
    var length = _length;
    for (var i = start; i < end; i++) {
      // Compress?
      if (length % _blockSizeInBytes == 0 && length > 0) {
        _length = length;
        _compress(false);
      }

      // Set byte
      bufferAsBytes[length % _blockSizeInBytes] = chunk[i];

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

    // Unfinished block?
    final length = _length;
    if (length == 0 || length % _blockSizeInBytes != 0) {
      for (var i = length % _blockSizeInBytes; i < _blockSizeInBytes; i++) {
        _bufferAsBytes[i] = 0;
      }
    }
    _compress(true);
  }

  @override
  void initializeSync({
    required SecretKeyData secretKey,
    required List<int> nonce,
    List<int> aad = const [],
  }) {
    final secretKeyBytes = secretKey.bytes;
    if (secretKeyBytes.length > _maxKeySizeInBytes) {
      throw ArgumentError.value(hashLengthInBytes, 'secretKey');
    }
    _initialize(key: secretKeyBytes);
  }

  @override
  void reset() {
    _initialize(key: null);
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

    // 12 rounds
    for (var round = 0; round < 12; round++) {
      // Sigma index
      final si = round * 16;

      // Each 64-bit integer takes two elements in the Uint32List,
      // so we need to multiply the indices.
      g(v, 0, 8, 16, 24, m, _sigma[si + 0], _sigma[si + 1]);
      g(v, 2, 10, 18, 26, m, _sigma[si + 2], _sigma[si + 3]);
      g(v, 4, 12, 20, 28, m, _sigma[si + 4], _sigma[si + 5]);
      g(v, 6, 14, 22, 30, m, _sigma[si + 6], _sigma[si + 7]);

      g(v, 0, 10, 20, 30, m, _sigma[si + 8], _sigma[si + 9]);
      g(v, 2, 12, 22, 24, m, _sigma[si + 10], _sigma[si + 11]);
      g(v, 4, 14, 16, 26, m, _sigma[si + 12], _sigma[si + 13]);
      g(v, 6, 8, 18, 28, m, _sigma[si + 14], _sigma[si + 15]);
    }

    // Copy.
    for (var i = 0; i < 16; i++) {
      h[i] = h[i] ^ v[i] ^ v[16 + i];
    }
  }

  void _initialize({
    required List<int>? key,
  }) {
    _isClosed = false;
    _length = 0;
    _bufferAsUint32List.fillRange(0, _bufferAsUint32List.length, 0);
    _localValues.fillRange(0, _localValues.length, 0);

    final h = _hash;
    h.setAll(0, _initializationVector);
    h[0] ^=
        0x01010000 ^ (key == null ? 0 : key.length << 8) ^ hashLengthInBytes;

    // If we have a key, add it
    if (key != null) {
      final keyLength = key.length;
      if (keyLength > _maxKeySizeInBytes) {
        throw ArgumentError();
      }
      add(key);
      add(Uint8List(_blockSizeInBytes - keyLength % _blockSizeInBytes));
    }
  }

  /// Exported so this can be used by both:
  ///   * [DartBlake2b]
  ///   * [DartArgon2id]
  static void g(
    Uint32List v,
    int a,
    int b,
    int c,
    int d,
    Uint32List m,
    int x,
    int y,
  ) {
    // Each 64-bit integer takes two elements in the Uint32List,
    // so we need to multiply the indices.
    x *= 2;
    y *= 2;

    var vaLow = v[a];
    var vaHigh = v[a + 1];
    var vbLow = v[b];
    var vbHigh = v[b + 1];
    var vcLow = v[c];
    var vcHigh = v[c + 1];
    var vdLow = v[d];
    var vdHigh = v[d + 1];

    // va = va + bv + m[x]
    {
      final low = vaLow + vbLow + m[x];
      vaLow = uint32mask & low;
      vaHigh = uint32mask & (low ~/ _bit32 + vaHigh + vbHigh + m[x + 1]);
    }

    // vd = rotateRight(vd ^ va, 32);
    {
      final low = vdLow ^ vaLow;
      final high = vdHigh ^ vaHigh;
      vdLow = high;
      vdHigh = low;
    }

    // vc = c + d
    {
      final low = vcLow + vdLow;
      vcLow = uint32mask & low;
      vcHigh = uint32mask & (low ~/ _bit32 + vcHigh + vdHigh);
    }

    // vb = rotateRight(b ^ c, 24);
    {
      final low = vbLow ^ vcLow;
      final high = vbHigh ^ vcHigh;
      vbLow = ((high << 8)) | low >> 24;
      vbHigh = ((low << 8)) | high >> 24;
    }

    // va = va + vb + m[y]
    {
      final low = vaLow + vbLow + m[y];
      vaLow = uint32mask & low;
      vaHigh = uint32mask & (low ~/ _bit32 + vaHigh + vbHigh + m[y + 1]);
    }

    // vd = rotateRight(vd ^ va, 16);
    {
      final low = vdLow ^ vaLow;
      final high = vdHigh ^ vaHigh;
      vdLow = (high << 16) | low >> 16;
      vdHigh = (low << 16) | high >> 16;
    }

    // vc = c + d
    {
      final low = vcLow + vdLow;
      vcLow = uint32mask & low;
      vcHigh = uint32mask & (low ~/ _bit32 + vcHigh + vdHigh);
    }

    // vb = rotateRight(vb ^ vc, 63);
    {
      final low = vbLow ^ vcLow;
      final high = vbHigh ^ vcHigh;
      vbLow = (low << 1) | (high >> 31);
      vbHigh = (high << 1) | (low >> 31);
    }
    v[a] = vaLow;
    v[a + 1] = vaHigh;
    v[b] = vbLow;
    v[b + 1] = vbHigh;
    v[c] = vcLow;
    v[c + 1] = vcHigh;
    v[d] = vdLow;
    v[d + 1] = vdHigh;
  }
}
