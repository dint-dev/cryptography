// Copyright 2019 Gohilla Ltd (https://gohilla.com).
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

/// HMAC ("hash-based message authentication code").
///
/// An example:
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// void main() {
///   final algorithm = const Hmac(sha256);
///   final mac = algorithm.calculateMac(
///     [1,2,3],
///     secretKey: SecretKey([1,2,3]),
///   );
///   sink.add(<int>[1,2,3]);
///   final hash = sink.closeSync();
/// }
/// ```
class Hmac extends MacAlgorithm {
  final HashAlgorithm hashAlgorithm;

  const Hmac(this.hashAlgorithm);

  @override
  MacSink newSink({@required SecretKey secretKey}) {
    ArgumentError.checkNotNull(secretKey);

    final hashAlgorithm = this.hashAlgorithm;
    final blockLength = hashAlgorithm.blockLength;

    //
    // secret
    //
    var hmacKey = secretKey.bytes;
    if (hmacKey.length > blockLength) {
      hmacKey = hashAlgorithm.hashSync(hmacKey).bytes;
    }

    //
    // inner sink
    //
    final innerSink = hashAlgorithm.newSink();
    final innerPadding = Uint8List(blockLength);
    _preparePadding(innerPadding, hmacKey, 0x36);
    innerSink.add(innerPadding);

    //
    // outer sink
    //
    final outerSink = hashAlgorithm.newSink();
    final outerPadding = Uint8List(blockLength);
    _preparePadding(outerPadding, hmacKey, 0x5c);
    outerSink.add(outerPadding);

    return _HmacSink(innerSink, outerSink);
  }

  @override
  String toString() => 'Hmac(${hashAlgorithm.name})';

  static void _preparePadding(List<int> padding, List<int> key, int byte) {
    for (var i = 0; i < padding.length; i++) {
      padding[i] = i < key.length ? (key[i] ^ byte) : byte;
    }
  }
}

class _HmacSink extends MacSink {
  final HashSink _innerSink;
  final HashSink _outerSink;
  bool _isClosed = false;

  _HmacSink(this._innerSink, this._outerSink);

  @override
  void add(List<int> bytes) {
    _innerSink.add(bytes);
  }

  @override
  void addSlice(List<int> chunk, int start, int end, bool isLast) {
    _innerSink.addSlice(chunk, start, end, isLast);
  }

  @override
  Mac closeSync() {
    if (_isClosed) throw StateError('The sink is closed');
    _isClosed = true;

    final innerHash = _innerSink.closeSync().bytes;

    final outerSink = _outerSink;
    outerSink.add(innerHash);
    final outerHash = outerSink.closeSync().bytes;

    return Mac(outerHash);
  }
}
