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

import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:cryptography_plus/dart.dart';
import 'package:meta/meta.dart';

/// [Poly1305] implemented in pure Dart.
///
/// For examples and more information about the algorithm, see documentation for
/// the class [Poly1305].
///
/// ## Known limitations
///   * Currently uses [BigInt], which makes the implementation slow.
class DartPoly1305 extends Poly1305 with DartMacAlgorithmMixin {
  const DartPoly1305() : super.constructor();

  @override
  DartPoly1305Sink newMacSinkSync({
    required SecretKeyData secretKeyData,
    List<int> nonce = const <int>[],
    List<int> aad = const <int>[],
  }) {
    if (aad.isNotEmpty) {
      throw ArgumentError.value(
        aad,
        'aad',
        'AAD is not supported',
      );
    }

    final result = DartPoly1305Sink();
    result.initializeSync(
      secretKey: secretKeyData,
      nonce: nonce,
      aad: aad,
    );
    return result;
  }

  @override
  DartPoly1305 toSync() => this;
}

/// [MacSink] for [DartPoly1305].
class DartPoly1305Sink extends MacSink with DartMacSinkMixin {
  final _buffer = ByteData(20);
  final _a = Uint16List(10);
  final _r = Uint16List(10);
  final _s = Uint16List(8);
  final _tmp = Uint32List(10);
  int _blockLength = 0;
  bool _isClosed = false;
  Mac? _mac;
  int _length = 0;

  DartPoly1305Sink();

  @override
  // TODO: implement isClosed
  bool get isClosed => _isClosed;

  int get length => _length;

  @override
  // TODO: implement macStateAsUint8List
  Uint8List get macBytes => _mac!.bytes as Uint8List;

  @mustCallSuper
  @override
  void addSlice(List<int> chunk, int start, int end, bool isLast) {
    if (isClosed) {
      throw StateError('Closed already');
    }
    RangeError.checkValidRange(start, end, chunk.length);

    // We need to support browsers, which don't have 64-bit integers.
    //
    // We originally had a BigInt implementation, but it was slow.
    // This new implementation uses 16-bit integer arrays.
    //
    // The implementation has been inspired by "poly1305-donna-16.h" by Andrew
    // Moon, which has "MIT or PUBLIC DOMAIN" license. It can be found at:
    // https://github.com/floodyberry/poly1305-donna/blob/master/poly1305-donna-16.h
    final chunkLength = end - start;
    if (chunkLength > 0) {
      // Increment length
      _length += chunkLength;

      // For each byte
      final buffer = _buffer;
      var blockLength = _blockLength;
      for (var i = start; i < end; i++) {
        // Set byte
        buffer.setUint8(blockLength, chunk[i]);
        blockLength++;

        // Full block?
        if (blockLength == 16) {
          buffer.setUint8(16, 1);
          process(
            block: buffer,
            blockLength: 16,
            a: _a,
            r: _r,
            s: _s,
            tmp: _tmp,
            isLast: false,
          );
          blockLength = 0;
        }
      }
      _blockLength = blockLength;
    }

    if (isLast) {
      // Call a protected method we needed for implementing
      // ChaCha20-Poly1305-AEAD
      afterData();

      // Final block
      _finalize();
    }
  }

  /// A protected method required by
  /// [DartChacha20Poly1305AeadMacAlgorithm] implementation.
  @protected
  void afterData() {}

  /// A protected method required by
  /// [DartChacha20Poly1305AeadMacAlgorithm] implementation.
  @protected
  void beforeData({
    required SecretKeyData secretKey,
    required List<int> nonce,
    required List<int> aad,
  }) {
    if (aad.isNotEmpty) {
      throw ArgumentError.value(aad, 'aad');
    }
  }

  @override
  void close() {
    addSlice(const [], 0, 0, true);
  }

  @mustCallSuper
  @override
  void initializeSync({
    required SecretKeyData secretKey,
    required List<int> nonce,
    List<int> aad = const [],
  }) {
    _blockLength = 0;
    _isClosed = false;
    _mac = null;
    _length = 0;

    // RFC variable `r`
    final r = _r;
    final keyBytes = secretKey.bytes;

    final key = Uint16List.view(
      keyBytes is Uint8List
          ? keyBytes.buffer
          : Uint8List.fromList(keyBytes).buffer,
    );

    // In RFC:
    //  r = (le_bytes_to_num(key[0..15])
    //  clamp(r)
    final k0 = key[0];
    r[0] = 0x1FFF & k0;
    final k1 = key[1];
    r[1] = 0x1FFF & ((k0 >> 13) | (k1 << 3));
    final k2 = key[2];
    r[2] = 0x1F03 & ((k1 >> 10) | (k2 << 6));
    final k3 = key[3];
    r[3] = 0x1FFF & ((k2 >> 7) | (k3 << 9));
    r[4] = 0xFF & (k3 >> 4);
    final k4 = key[4];
    r[5] = 0x1FFE & (k4 >> 1);
    final k5 = key[5];
    r[6] = 0x1FFF & ((k4 >> 14) | (k5 << 2));
    final k6 = key[6];
    r[7] = 0x1F81 & ((k5 >> 11) | (k6 << 5));
    final k7 = key[7];
    r[8] = 0x1FFF & ((k6 >> 8) | (k7 << 8));
    r[9] = 0x7F & (k7 >> 5);

    // In RFC:
    // s = le_num(key[16..31])
    final s = _s;
    final sBytes = Uint8List.view(s.buffer);
    for (var i = 0; i < 16; i++) {
      sBytes[i] = keyBytes[16 + i];
    }

    // Erase helper `h`
    final h = _a;
    for (var i = 0; i < 10; i++) {
      h[i] = 0;
    }

    final buffer = _buffer;
    buffer.setUint32(0, 0);
    buffer.setUint32(4, 0);
    buffer.setUint32(8, 0);
    buffer.setUint32(12, 0);
    buffer.setUint32(16, 0);

    beforeData(
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
    );
  }

  @override
  Mac macSync() => _mac!;

  void _finalize() {
    _isClosed = true;

    if (_blockLength > 0 || length == 0) {
      final buffer = _buffer;
      buffer.setUint8(_blockLength, 1);
      for (var i = _blockLength + 1; i < buffer.lengthInBytes; i++) {
        buffer.setUint8(i, 0);
      }
      process(
        block: buffer,
        blockLength: 16,
        a: _a,
        r: _r,
        s: _s,
        tmp: _tmp,
        isLast: true,
      );
    }

    final a = _a;
    final s = _s;
    // Carry a
    {
      var a1 = a[1];
      var carry = a1 >> 13;
      a[1] = 0x1FFF & a1;
      for (var i = 2; i < 10; i++) {
        a[i] += carry;
        carry = a[i] >> 13;
        a[i] &= 0x1FFF;
      }
      a[0] += 5 * carry;
      carry = a[0] >> 13;
      a[0] &= 0x1FFF;
      a[1] += carry;
      carry = a[1] >> 13;
      a[1] &= 0x1FFF;
      a[2] += carry;
    }

    // a + -p
    {
      final tmp = _tmp;
      var tmp0 = 5 + a[0];
      var carry = tmp0 >> 13;
      tmp[0] = 0x1FFF & tmp0;
      for (var i = 1; i < 10; i++) {
        tmp[i] = a[i] + carry;
        carry = tmp[i] >> 13;
        tmp[i] &= 0x1FFF;
      }
      var mask = (carry ^ 1) - 1;
      for (var i = 0; i < 10; i++) {
        tmp[i] &= mask;
      }
      mask = ~mask;
      for (var i = 0; i < 10; i++) {
        a[i] = tmp[i] | (a[i] & mask);
      }
    }

    // a = a % 2^128
    {
      a[0] = a[0] | (a[1] << 13);
      a[1] = (a[1] >> 3) | (a[2] << 10);
      a[2] = (a[2] >> 6) | (a[3] << 7);
      a[3] = (a[3] >> 9) | (a[4] << 4);
      a[4] = (a[4] >> 12) | (a[5] << 1) | (a[6] << 14);
      a[5] = (a[6] >> 2) | (a[7] << 11);
      a[6] = (a[7] >> 5) | (a[8] << 8);
      a[7] = (a[8] >> 8) | (a[9] << 5);
    }

    // In RFC:
    // a += s
    {
      var tmp = a[0] + s[0];
      a[0] = 0xFFFF & tmp;
      for (var i = 1; i < 8; i++) {
        final carry = tmp >> 16;
        tmp = a[i] + s[i] + carry;
        a[i] = 0xFFFF & tmp;
      }
    }

    final bytes = Uint8List(16);
    final data = bytes.buffer.asByteData();
    data.setUint16(0, a[0], Endian.little);
    data.setUint16(2, a[1], Endian.little);
    data.setUint16(4, a[2], Endian.little);
    data.setUint16(6, a[3], Endian.little);
    data.setUint16(8, a[4], Endian.little);
    data.setUint16(10, a[5], Endian.little);
    data.setUint16(12, a[6], Endian.little);
    data.setUint16(14, a[7], Endian.little);
    _mac = Mac(bytes);
  }

  static void process({
    required ByteData block,
    required Uint16List a,
    required Uint16List s,
    required Uint16List r,
    required Uint32List tmp,
    required int blockLength,
    required bool isLast,
  }) {
    //
    // Append 1
    //
    block.setUint8(blockLength, 1);
    for (var i = blockLength + 1; i < 17; i++) {
      block.setUint8(i, 0);
    }

    //
    // a += block
    //
    final t0 = block.getUint16(0, Endian.little);
    a[0] += 0x1FFF & t0;

    final t1 = block.getUint16(2, Endian.little);
    a[1] += 0x1FFF & ((t0 >> 13) | (t1 << 3));

    final t2 = block.getUint16(4, Endian.little);
    a[2] += 0x1FFF & ((t1 >> 10) | (t2 << 6));

    final t3 = block.getUint16(6, Endian.little);
    a[3] += 0x1FFF & ((t2 >> 7) | (t3 << 9));

    final t4 = block.getUint16(8, Endian.little);
    a[4] += 0x1FFF & ((t3 >> 4) | (t4 << 12));
    a[5] += 0x1FFF & (t4 >> 1);

    final t5 = block.getUint16(10, Endian.little);
    a[6] += 0x1FFF & ((t4 >> 14) | (t5 << 2));

    final t6 = block.getUint16(12, Endian.little);
    a[7] += 0x1FFF & ((t5 >> 11) | (t6 << 5));

    final t7 = block.getUint16(14, Endian.little);
    a[8] += 0x1FFF & ((t6 >> 8) | (t7 << 8));
    a[9] += (t7 >> 5) | (isLast ? 0 : (1 << 11));

    // In RFC:
    // a = (r * a) % p
    var carry = 0;
    for (var i = 0; i < 10; i++) {
      tmp[i] = carry;
      for (var j = 0; j < 10; j++) {
        final x = (j <= i) ? r[i - j] : (5 * r[10 + i - j]);
        tmp[i] += a[j] * x;
        if (j == 4) {
          carry = tmp[i] >> 13;
          tmp[i] = 0x1FFF & tmp[i];
        }
      }
      carry += tmp[i] >> 13;
      tmp[i] = 0x1FFF & tmp[i];
    }
    carry = (carry << 2) + carry;
    carry += tmp[0];
    tmp[0] = 0x1FFF & carry;
    carry = carry >> 13;
    tmp[1] += carry;
    for (var i = 0; i < 10; i++) {
      a[i] = 0xFFFF & tmp[i];
    }
  }
}
