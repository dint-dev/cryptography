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

/// [Poly1305] implemented in pure Dart.
///
/// ## Known limitations
///   * Currently uses [BigInt]
class DartPoly1305 extends Poly1305 {
  const DartPoly1305() : super.constructor();

  @override
  Future<Mac> calculateMac(
    List<int> input, {
    required SecretKey secretKey,
    List<int> nonce = const <int>[],
    List<int> aad = const <int>[],
  }) async {
    final sink = await newMacSink(
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
    );
    sink.addSlice(input, 0, input.length, true);
    sink.close();
    return sink.mac();
  }

  @override
  Future<MacSink> newMacSink({
    required SecretKey secretKey,
    List<int> nonce = const <int>[],
    List<int> aad = const <int>[],
  }) async {
    if (aad.isNotEmpty) {
      throw ArgumentError.value(aad, 'aad', 'AAD is not supported');
    }
    final secretKeyBytes = await secretKey.extractBytes();

    // RFC variable `r`
    final r = ByteData(20);
    for (var i = 0; i < 16; i++) {
      r.setUint8(i, secretKeyBytes[i]);
    }
    r.setUint8(3, 15 & r.getUint8(3));
    r.setUint8(4, 252 & r.getUint8(4));
    r.setUint8(7, 15 & r.getUint8(7));
    r.setUint8(8, 252 & r.getUint8(8));
    r.setUint8(11, 15 & r.getUint8(11));
    r.setUint8(12, 252 & r.getUint8(12));
    r.setUint8(15, 15 & r.getUint8(15));

    // RFC variable `s`
    final s = ByteData(20);
    for (var i = 0; i < 16; i++) {
      s.setUint8(i, secretKeyBytes[16 + i]);
    }

    return _Poly1305Sink(r, s);
  }
}

class _Poly1305Sink extends MacSink {
  static final _p = BigInt.two.pow(130) - BigInt.from(5);
  static final _mask32 = BigInt.from(0xFFFFFFFF);
  final ByteData _buffer = ByteData(20);
  final ByteData _r;
  final ByteData _s;
  int _h0 = 0;
  int _h1 = 0;
  int _h2 = 0;
  int _h3 = 0;
  int _h4 = 0;
  int _bufferLength = 0;

  bool _isClosed = false;

  Mac? _mac;

  _Poly1305Sink(this._r, this._s);

  @override
  void addSlice(List<int> chunk, int start, int end, bool isLast) {
    if (_isClosed) {
      throw StateError('Closed already');
    }
    final buffer = _buffer;
    var bufferLength = _bufferLength;
    for (var i = start; i < end; i++) {
      if (bufferLength == 16) {
        _bufferLength = bufferLength;
        _processBlock();
        bufferLength = 0;
      }
      buffer.setUint8(bufferLength, chunk[i]);
      bufferLength++;
    }
    _bufferLength = bufferLength;
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

    _processBlock();

    var h0 = _h0;
    var h1 = _h1;
    var h2 = _h2;
    var h3 = _h3;
    _h0 = 0;
    _h1 = 0;
    _h2 = 0;
    _h3 = 0;
    _h4 = 0;

    //
    // h += s
    //
    final s = _s;
    const bit32 = 0x100000000;
    h0 += s.getUint32(0, Endian.little);
    h1 += h0 ~/ bit32;
    h0 %= bit32;

    h1 += s.getUint32(4, Endian.little);
    h2 += h1 ~/ bit32;
    h1 %= bit32;

    h2 += s.getUint32(8, Endian.little);
    h3 += h2 ~/ bit32;
    h2 %= bit32;

    h3 += s.getUint32(12, Endian.little);
    h3 %= bit32;

    final data = ByteData(16);
    data.setUint32(0, h0, Endian.little);
    data.setUint32(4, h1, Endian.little);
    data.setUint32(8, h2, Endian.little);
    data.setUint32(12, h3, Endian.little);
    _mac = Mac(List<int>.unmodifiable(
      Uint8List.view(data.buffer),
    ));
  }

  @override
  Future<Mac> mac() async => _mac!;

  void _processBlock() {
    var h0 = _h0;
    var h1 = _h1;
    var h2 = _h2;
    var h3 = _h3;
    var h4 = _h4;

    const bit32 = 0x100000000;

    //
    // Append 1
    //

    final buffer = _buffer;
    buffer.setUint8(_bufferLength, 1);

    //
    // h += block
    //

    h0 += buffer.getUint32(0, Endian.little);
    h1 += h0 ~/ bit32;
    h0 %= bit32;

    h1 += buffer.getUint32(4, Endian.little);
    h2 += h1 ~/ bit32;
    h1 %= bit32;

    h2 += buffer.getUint32(8, Endian.little);
    h3 += h2 ~/ bit32;
    h2 %= bit32;

    h3 += buffer.getUint32(12, Endian.little);
    h4 += h3 ~/ bit32;
    h3 %= bit32;

    h4 += buffer.getUint32(16, Endian.little);

    // Clear buffer
    buffer.setUint32(0, 0);
    buffer.setUint32(4, 0);
    buffer.setUint32(8, 0);
    buffer.setUint32(12, 0);
    buffer.setUint32(16, 0);

    //
    // h = (h * r) % 2^130 - 5
    //

    final r = _r;
    final a0 = r.getUint32(0, Endian.little);
    final a1 = r.getUint32(4, Endian.little);
    final a2 = r.getUint32(8, Endian.little);
    final a3 = r.getUint32(12, Endian.little);
    final a4 = r.getUint32(16, Endian.little);

    // TODO: A performance & security improvement by eliminating use of BigInt!

    var hBigInt = BigInt.from(h0) +
        (BigInt.from(h1) << 32) +
        (BigInt.from(h2) << 64) +
        (BigInt.from(h3) << 96) +
        (BigInt.from(h4) << 128);

    final aBigInt = BigInt.from(a0) +
        (BigInt.from(a1) << 32) +
        (BigInt.from(a2) << 64) +
        (BigInt.from(a3) << 96) +
        (BigInt.from(a4) << 128);

    hBigInt = (hBigInt * aBigInt) % _p;

    final mask = _mask32;
    h0 = (mask & hBigInt).toInt();
    h1 = (mask & (hBigInt >> 32)).toInt();
    h2 = (mask & (hBigInt >> 64)).toInt();
    h3 = (mask & (hBigInt >> 96)).toInt();
    h4 = (hBigInt >> 128).toInt();

    _h0 = h0;
    _h1 = h1;
    _h2 = h2;
    _h3 = h3;
    _h4 = h4;
  }
}
