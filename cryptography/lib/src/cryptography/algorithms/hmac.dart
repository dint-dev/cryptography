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

/// HMAC ("hash-based message authentication code").
///
/// An example:
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() {
///   final secretKey = SecretKey([1,2,3]);
///
///   // Create a sink
///   final sink = Hmac(sha256).newSink(
///     secretKey: secretKey,
///   );
///
///   // Add parts
///   sink.add([1,2,3]);
///   sink.add([4,5]);
///
///   // Calculate MAC
///   sink.close();
///   final mac = sink.mac;
/// }
/// ```
class Hmac extends MacAlgorithm {
  /// Hash algorithm used by this HMAC.
  final HashAlgorithm hashAlgorithm;

  const Hmac(this.hashAlgorithm);

  @override
  int get macLengthInBytes => hashAlgorithm.hashLengthInBytes;

  @override
  String get name => 'Hmac(${hashAlgorithm.name})';

  @override
  MacSink newSink({@required SecretKey secretKey}) {
    ArgumentError.checkNotNull(secretKey);

    final hashAlgorithm = this.hashAlgorithm;
    final blockLength = hashAlgorithm.blockLengthInBytes;

    //
    // secret
    //
    var hmacKey = secretKey.extractSync();
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
  Mac _mac;

  _HmacSink(this._innerSink, this._outerSink);

  @override
  Mac get mac => _mac;

  @override
  void add(List<int> bytes) {
    if (_isClosed) {
      throw StateError('Already closed.');
    }
    _innerSink.add(bytes);
  }

  @override
  void addSlice(List<int> chunk, int start, int end, bool isLast) {
    if (_isClosed) {
      throw StateError('Already closed.');
    }
    _innerSink.addSlice(chunk, start, end, isLast);
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
    _innerSink.close();
    final outerSink = _outerSink;
    outerSink.add(_innerSink.hash.bytes);
    outerSink.close();
    _mac = Mac(outerSink.hash.bytes);
  }
}
