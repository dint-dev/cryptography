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

import 'package:cryptography_plus/src/cryptography/secret_key.dart';

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

  /// Hash: 8 x uint64
  final _hash = Uint64List(8);

  /// Hash: N bytes (N <= 64)
  @override
  late final Uint8List hashBytes = Uint8List.view(
    _hash.buffer,
    0,
    hashLengthInBytes,
  );

  /// Buffer for writing data: 16 x uint64
  final _bufferAsUint64List = Uint64List(16);

  /// Buffer for writing data: 128 bytes
  late final Uint8List _bufferAsBytes = Uint8List.view(
    _bufferAsUint64List.buffer,
  );

  /// State of the hash: 16 x uint64
  final _localValues = Uint64List(16);

  /// Total length so far.
  int _length = 0;

  /// Whether [close] was called.
  bool _isClosed = false;

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
    if (isClosed) {
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
      throw ArgumentError('Too large secret key: ${secretKey.bytes.length}');
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

    for (var round = 0; round < 12; round++) {
      // Sigma index
      final si = round * 16;

      g(v, 0, 4, 8, 12, m, _sigma[si + 0], _sigma[si + 1]);
      g(v, 1, 5, 9, 13, m, _sigma[si + 2], _sigma[si + 3]);
      g(v, 2, 6, 10, 14, m, _sigma[si + 4], _sigma[si + 5]);
      g(v, 3, 7, 11, 15, m, _sigma[si + 6], _sigma[si + 7]);

      g(v, 0, 5, 10, 15, m, _sigma[si + 8], _sigma[si + 9]);
      g(v, 1, 6, 11, 12, m, _sigma[si + 10], _sigma[si + 11]);
      g(v, 2, 7, 8, 13, m, _sigma[si + 12], _sigma[si + 13]);
      g(v, 3, 4, 9, 14, m, _sigma[si + 14], _sigma[si + 15]);
    }

    // Copy.
    for (var i = 0; i < 8; i++) {
      h[i] ^= v[i] ^ v[8 + i];
    }
  }

  void _initialize({
    required List<int>? key,
  }) {
    _isClosed = false;
    _length = 0;
    _bufferAsUint64List.fillRange(0, _bufferAsUint64List.length, 0);
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
      vd = (arg >>> n) | (arg << (64 - n));
    }
    vc += vd;
    {
      // vb = rotateRight(vb ^ vc, 24)
      final rotated = vb ^ vc;
      const n = 24;
      vb = (rotated >>> n) | (rotated << (64 - n));
    }
    va += vb + m[y];
    {
      // vd = rotateRight(vd ^ va, 16)
      final arg = vd ^ va;
      const n = 16;
      vd = (arg >>> n) | (arg << (64 - n));
    }
    vc += vd;
    {
      // vb = rotateRight(vb ^ vc, 63)
      final rotated = vb ^ vc;
      vb = (rotated << 1) | (rotated >>> 63);
    }
    v[a] = va;
    v[b] = vb;
    v[c] = vc;
    v[d] = vd;
  }
}
