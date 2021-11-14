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
import 'package:cryptography/dart.dart';

/// An implementation of [Hmac] in pure Dart.
class DartHmac extends Hmac with DartMacAlgorithmMixin {
  /// Hash algorithm used by this HMAC.
  @override
  final HashAlgorithm hashAlgorithm;

  const DartHmac(this.hashAlgorithm) : super.constructor();

  @override
  Future<Mac> calculateMac(
    List<int> bytes, {
    required SecretKey secretKey,
    List<int> nonce = const <int>[],
    List<int> aad = const <int>[],
  }) async {
    if (aad.isNotEmpty) {
      throw ArgumentError.value(
        aad,
        'aad',
        'AAD is not supported',
      );
    }
    final secretKeyData = await secretKey.extract();
    var hmacKey = secretKeyData.bytes;
    if (hmacKey.isEmpty) {
      throw ArgumentError.value(
        secretKey,
        'secretKey',
        'Must be non-empty',
      );
    }

    final hashAlgorithm = this.hashAlgorithm;

    final blockLength = hashAlgorithm.blockLengthInBytes;
    if (hmacKey.length > blockLength) {
      hmacKey = (await hashAlgorithm.hash(hmacKey)).bytes;
    }

    // Inner hash
    final innerPadding = Uint8List(blockLength);
    _preparePadding(innerPadding, hmacKey, 0x36);
    final innerInput = Uint8List(innerPadding.length + bytes.length);
    innerInput.setAll(0, innerPadding);
    innerInput.setAll(innerPadding.length, bytes);
    final innerHash = await hashAlgorithm.hash(innerInput);

    // Outer hash
    final outerPadding = Uint8List(blockLength);
    _preparePadding(outerPadding, hmacKey, 0x5c);
    final outerInput = Uint8List(outerPadding.length + innerHash.bytes.length);
    outerInput.setAll(0, outerPadding);
    outerInput.setAll(outerPadding.length, innerHash.bytes);
    final outerHash = await hashAlgorithm.hash(outerInput);

    return Mac(outerHash.bytes);
  }

  /// Synchronous version of [calculateMac].
  ///
  /// Throws [UnsupportedError] if [hashAlgorithm] does not support synchronous
  /// evaluation (it's not a subclass of [DartHashAlgorithmMixin]).
  ///
  /// For other parameters, see documentation of [calculateMac].
  @override
  Mac calculateMacSync(
    List<int> input, {
    required SecretKeyData secretKeyData,
    List<int> nonce = const <int>[],
    List<int> aad = const <int>[],
  }) {
    final hashAlgorithm = this.hashAlgorithm as DartHashAlgorithmMixin;
    if (aad.isNotEmpty) {
      throw ArgumentError.value(aad, 'aad', 'AAD is not supported');
    }
    var hmacKey = secretKeyData.bytes;
    if (hmacKey.isEmpty) {
      throw ArgumentError.value(
        secretKeyData,
        'secretKeyData',
        'Must be non-empty',
      );
    }

    final blockLength = hashAlgorithm.blockLengthInBytes;
    if (hmacKey.length > blockLength) {
      hmacKey = hashAlgorithm.hashSync(hmacKey).bytes;
    }

    // Inner hash
    final innerPadding = Uint8List(blockLength);
    _preparePadding(innerPadding, hmacKey, 0x36);
    final innerInput = Uint8List(innerPadding.length + input.length);
    innerInput.setAll(0, innerPadding);
    innerInput.setAll(innerPadding.length, input);
    final innerHash = hashAlgorithm.hashSync(innerInput);

    // Outer hash
    final outerPadding = Uint8List(blockLength);
    _preparePadding(outerPadding, hmacKey, 0x5c);
    final outerInput = Uint8List(outerPadding.length + innerHash.bytes.length);
    outerInput.setAll(0, outerPadding);
    outerInput.setAll(outerPadding.length, innerHash.bytes);
    final outerHash = hashAlgorithm.hashSync(outerInput);

    return Mac(outerHash.bytes);
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

    final hashAlgorithm = this.hashAlgorithm;
    final blockLength = hashAlgorithm.blockLengthInBytes;

    //
    // secret
    //
    final secretKeyData = await secretKey.extract();
    var hmacKey = secretKeyData.bytes;
    if (hmacKey.isEmpty) {
      throw ArgumentError.value(
        secretKey,
        'secretKey',
        'SecretKey bytes must be non-empty',
      );
    }
    if (hmacKey.length > blockLength) {
      hmacKey = (await hashAlgorithm.hash(hmacKey)).bytes;
    }

    //
    // inner sink
    //
    final innerSink = hashAlgorithm.newHashSink();
    final innerPadding = Uint8List(blockLength);
    _preparePadding(innerPadding, hmacKey, 0x36);
    innerSink.add(innerPadding);

    //
    // outer sink
    //
    final outerSink = hashAlgorithm.newHashSink();
    final outerPadding = Uint8List(blockLength);
    _preparePadding(outerPadding, hmacKey, 0x5c);
    outerSink.add(outerPadding);

    return _HmacSink(innerSink, outerSink);
  }

  @override
  DartMacSink newMacSinkSync({
    required SecretKeyData secretKeyData,
    List<int> nonce = const <int>[],
    List<int> aad = const <int>[],
  }) {
    if (aad.isNotEmpty) {
      throw ArgumentError.value(aad, 'aad', 'AAD is not supported');
    }

    final hashAlgorithm = this.hashAlgorithm;
    final blockLength = hashAlgorithm.blockLengthInBytes;

    //
    // secret
    //
    var hmacKey = secretKeyData.bytes;
    if (hmacKey.isEmpty) {
      throw ArgumentError.value(
        secretKeyData,
        'secretKeyData',
        'SecretKeyData bytes must be non-empty',
      );
    }
    if (hmacKey.length > blockLength) {
      final dartHashAlgorithm = hashAlgorithm as DartHashAlgorithmMixin;
      hmacKey = dartHashAlgorithm.hashSync(hmacKey).bytes;
    }

    //
    // inner sink
    //
    final innerSink = hashAlgorithm.newHashSink();
    final innerPadding = Uint8List(blockLength);
    _preparePadding(innerPadding, hmacKey, 0x36);
    innerSink.add(innerPadding);

    //
    // outer sink
    //
    final outerSink = hashAlgorithm.newHashSink();
    final outerPadding = Uint8List(blockLength);
    _preparePadding(outerPadding, hmacKey, 0x5c);
    outerSink.add(outerPadding);

    return _HmacSink(innerSink, outerSink);
  }

  static void _preparePadding(List<int> padding, List<int> key, int byte) {
    for (var i = 0; i < padding.length; i++) {
      padding[i] = i < key.length ? (key[i] ^ byte) : byte;
    }
  }
}

class _HmacSink extends MacSink with DartMacSink {
  final HashSink _innerSink;
  final HashSink _outerSink;
  bool _isClosed = false;

  Future<Mac>? _macFuture;

  _HmacSink(this._innerSink, this._outerSink);

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
    _isClosed = true;
  }

  @override
  Future<Mac> mac() {
    if (!_isClosed) {
      throw StateError('Sink is not closed');
    }
    return _macFuture ??= () async {
      final innerSink = _innerSink;
      innerSink.close();
      final innerHash = await innerSink.hash();
      final outerSink = _outerSink;
      outerSink.add(innerHash.bytes);
      outerSink.close();
      final outerHash = await outerSink.hash();
      return Mac(outerHash.bytes);
    }();
  }

  @override
  Mac macSync() {
    if (!_isClosed) {
      throw StateError('Sink is not closed');
    }
    final innerSink = _innerSink as DartHashSink;
    innerSink.close();
    final innerHash = innerSink.hashSync();
    final outerSink = _outerSink as DartHashSink;
    outerSink.add(innerHash.bytes);
    outerSink.close();
    final outerHash = outerSink.hashSync();
    return Mac(outerHash.bytes);
  }
}
