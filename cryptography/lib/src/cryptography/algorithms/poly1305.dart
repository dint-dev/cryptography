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
import 'package:meta/meta.dart';

/// _Poly1305_ message authentication algorithm
/// ([RFC 7539](https://tools.ietf.org/html/rfc7539)).
///
/// Remember that:
///   * You must not use the same key and nonce combination twice.
///   * You can't use it for key derivation because the algorithm is biased.
const MacAlgorithm poly1305 = _Poly1305();

/// Calculates a Poly1305 secret key by using Chacha20.
SecretKey poly1305SecretKeyFromChacha20(SecretKey secretKey,
    {@required Nonce nonce}) {
  final cipherText = chacha20.encryptSync(
    Uint8List(32),
    secretKey: secretKey,
    nonce: nonce,
  );
  return SecretKey(cipherText);
}

class _Poly1305 extends MacAlgorithm {
  const _Poly1305();

  @override
  int get macLengthInBytes => 16;

  @override
  String get name => 'poly1305';

  @override
  MacSink newSink({@required SecretKey secretKey}) {
    ArgumentError.checkNotNull(secretKey, 'secretKey');
    final secretKeyBytes = secretKey.extractSync();
    final r = _Poly1305Sink._bytesToBigInt(secretKeyBytes, 0, 16);
    final p = _Poly1305Sink._bytesToBigInt(secretKeyBytes, 16, 32);
    return _Poly1305Sink(r, p);
  }
}

class _Poly1305Sink extends MacSink {
  //
  // TODO: 128-bit add/multiply/remainder without BigInt
  //
  static final _rClamper = BigInt.parse(
    '0ffffffc0ffffffc0ffffffc0fffffff',
    radix: 16,
  );

  static final _p = BigInt.parse(
    '3fffffffffffffffffffffffffffffffb',
    radix: 16,
  );

  static final _sb = StringBuffer();
  final BigInt _r;
  final BigInt _s;
  final Uint8List _buffer = Uint8List(16);
  int _bufferLength = 0;
  BigInt _accumulator = BigInt.from(0);
  bool _isClosed = false;
  Mac _mac;

  _Poly1305Sink(BigInt r, this._s)
      : _r = r & _rClamper,
        assert(r != null),
        assert(_s != null);

  @override
  Mac get mac => _mac;

  @override
  void addSlice(List<int> chunk, int start, int end, bool isLast) {
    if (_isClosed) {
      throw StateError('Closed already');
    }
    ArgumentError.checkNotNull(chunk, 'chunk');
    ArgumentError.checkNotNull(start, 'start');
    ArgumentError.checkNotNull(end, 'end');
    final buffer = _buffer;
    var bufferLength = _bufferLength;
    for (var i = start; i < end; i++) {
      if (bufferLength == 16) {
        _accumulator = _round(
          accumulator: _accumulator,
          r: _r,
          block: buffer,
          blockLength: 16,
        );
        bufferLength = 0;
      }
      buffer[bufferLength] = chunk[i];
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
      throw StateError('Closed already');
    }
    _isClosed = true;
    final bigInt = (_round(
              accumulator: _accumulator,
              r: _r,
              block: _buffer,
              blockLength: _bufferLength,
            ) +
            _s) %
        (BigInt.one << 128);
    _mac = Mac(_bytesFromBigInt(bigInt));
  }

  static Uint8List _bytesFromBigInt(BigInt bigInt) {
    final s = bigInt.toRadixString(16).padLeft(32, '0');
    if (s.length > 32) {
      throw ArgumentError('More than 16 bytes');
    }
    final result = Uint8List((s.length + 1) ~/ 2);
    for (var i = 0; i < 16; i++) {
      result[15 - i] = int.parse(
        s.substring(2 * i, 2 * i + 2),
        radix: 16,
      );
    }
    return result;
  }

  static BigInt _bytesToBigInt(
    Uint8List bytes,
    int start,
    int end, {
    bool addBit128 = false,
  }) {
    final sb = _sb;
    if (addBit128) {
      sb.write('1');
    }
    for (var i = end - 1; i >= start; i--) {
      final b = bytes[i];
      sb.write((b >> 4).toRadixString(16));
      sb.write((0xF & b).toRadixString(16));
    }
    final bigInt = BigInt.parse(sb.toString(), radix: 16);
    sb.clear();
    return bigInt;
  }

  static BigInt _round({
    @required BigInt accumulator,
    @required BigInt r,
    @required Uint8List block,
    @required int blockLength,
  }) {
    final b = _bytesToBigInt(block, 0, blockLength, addBit128: true);
    return ((accumulator + b) * r) % _p;
  }
}
