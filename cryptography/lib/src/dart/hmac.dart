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

/// An implementation of [Hmac] in pure Dart.
///
/// Optional argument [nonce] does not affect the MAC. If optional argument
/// [aad] is not empty, [ArgumentError] is thrown.
///
/// For examples and more information about the algorithm, see documentation for
/// the class [Hmac].
///
/// ## Using synchronous methods
///
/// If you want to use synchronous methods ([calculateMacSync],
/// [newMacSinkSync]), the hash algorithm must be synchronous too.
///
/// For example, to compute HMAC-SHA256:
///
/// ```dart
/// final algorithm = DartHmac(DartSha256());
/// final mac = algorithm.calculateMac(bytes, secretKey: secretKey);
/// ```
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
    final sink = await newMacSink(
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
    );
    sink.add(bytes);
    sink.close();
    return await sink.mac();
  }

  /// Synchronous version of [calculateMac].
  ///
  /// Optional argument [nonce] does not affect the MAC. If optional argument
  /// [aad] is not empty, [ArgumentError] is thrown.
  ///
  /// Throws [UnsupportedError] if [hashAlgorithm] does not support synchronous
  /// evaluation (it's not a subclass of [DartHashAlgorithmMixin]).
  ///
  /// For example, to compute HMAC-SHA256:
  ///
  /// ```dart
  /// final algorithm = DartHmac(DartSha256());
  /// final mac = algorithm.calculateMac(bytes, secretKey: secretKey);
  /// ```
  @override
  Mac calculateMacSync(
    List<int> input, {
    required SecretKeyData secretKeyData,
    List<int> nonce = const <int>[],
    List<int> aad = const <int>[],
  }) {
    final sink = newMacSinkSync(
      secretKeyData: secretKeyData,
      nonce: nonce,
      aad: aad,
    );
    sink.add(input);
    sink.close();
    return sink.macSync();
  }

  /// Synchronous version of [newMacSink].
  ///
  /// Optional argument [nonce] does not affect the MAC. If optional argument
  /// [aad] is not empty, [ArgumentError] is thrown.
  ///
  /// Throws [UnsupportedError] if [hashAlgorithm] does not support synchronous
  /// evaluation (it's not a subclass of [DartHashAlgorithmMixin]).
  ///
  /// For example, to compute HMAC-SHA256:
  ///
  /// ```dart
  /// final algorithm = DartHmac(DartSha256());
  /// final mac = algorithm.calculateMac(bytes, secretKey: secretKey);
  /// ```
  @override
  Future<MacSink> newMacSink({
    required SecretKey secretKey,
    List<int> nonce = const <int>[],
    List<int> aad = const <int>[],
  }) async {
    final secretKeyData = await secretKey.extract();
    final blockLength = hashAlgorithm.blockLengthInBytes;
    if (aad.isNotEmpty) {
      throw ArgumentError.value(aad, 'aad', 'AAD is not supported');
    }
    if (secretKeyData.bytes.isEmpty) {
      throw ArgumentError.value(
        secretKeyData,
        'secretKeyData',
        'Secret key must be non-empty',
      );
    }
    if (secretKeyData.bytes.length > blockLength) {
      final hash =
          await hashAlgorithm.hash(Uint8List.fromList(secretKeyData.bytes));
      return _newMacSinkSync(hash.bytes, eraseKey: true);
    } else {
      return _newMacSinkSync(secretKeyData.bytes, eraseKey: false);
    }
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
    if (secretKeyData.bytes.isEmpty) {
      throw ArgumentError.value(
        secretKeyData,
        'secretKeyData',
        'Secret key must be non-empty',
      );
    }

    // Copy the bytes so destruction of the key won't affect.
    final blockLength = hashAlgorithm.blockLengthInBytes;
    if (secretKeyData.bytes.length > blockLength) {
      final dartHashAlgorithm = hashAlgorithm as DartHashAlgorithmMixin;
      final hash = dartHashAlgorithm.hashSync(secretKeyData.bytes);
      return _newMacSinkSync(hash.bytes, eraseKey: true);
    } else {
      return _newMacSinkSync(secretKeyData.bytes, eraseKey: false);
    }
  }

  DartMacSink _newMacSinkSync(List<int> hmacKey, {required bool eraseKey}) {
    // Make a copy
    final hashAlgorithm = this.hashAlgorithm;
    final blockLength = hashAlgorithm.blockLengthInBytes;
    if (hmacKey.length > blockLength) {
      throw ArgumentError();
    }

    // Allocate a temporary buffer
    final tmp = Uint8List(blockLength);

    // Initialize inner sink
    final innerSink = hashAlgorithm.newHashSink();
    _preparePadding(tmp, hmacKey, 0x36);
    innerSink.add(tmp);

    // Erase the temporary buffer
    tmp.fillRange(0, tmp.length, 0);

    // Initialize outer sink
    final outerSink = hashAlgorithm.newHashSink();
    _preparePadding(tmp, hmacKey, 0x5c);
    outerSink.add(tmp);

    // Erase copy of the secret key copy
    // (safer to not leave the data in memory)
    if (eraseKey && hmacKey is! UnmodifiableUint8ListView) {
      hmacKey.fillRange(0, hmacKey.length, 0);
    }

    // Erase the temporary buffer
    // (safer to not leave the data in memory)
    tmp.fillRange(0, tmp.length, 0);

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
