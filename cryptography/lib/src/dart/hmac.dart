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

/// An implementation of [Hmac] in pure Dart.
///
/// For examples and more information about the algorithm, see documentation for
/// the superclass [Hmac].
class DartHmac extends Hmac with DartMacAlgorithmMixin {
  /// Hash algorithm used by this HMAC.
  @override
  final HashAlgorithm hashAlgorithm;

  const DartHmac(this.hashAlgorithm) : super.constructor();

  /// HMAC-BLAKE2B.
  factory DartHmac.blake2b() => DartHmac(Blake2b());

  /// HMAC-BLAKE2S.
  factory DartHmac.blake2s() => DartHmac(Blake2s());

  /// HMAC-SHA1.
  factory DartHmac.sha1() => DartHmac(Sha1());

  /// HMAC-SHA224.
  factory DartHmac.sha224() => DartHmac(Sha224());

  /// HMAC-SHA256.
  factory DartHmac.sha256() => DartHmac(Sha256());

  /// HMAC-SHA384.
  factory DartHmac.sha384() => DartHmac(Sha384());

  /// HMAC-SHA512.
  factory DartHmac.sha512() => DartHmac(Sha512());

  @override
  DartMacSinkMixin newMacSinkSync({
    required SecretKeyData secretKeyData,
    List<int> nonce = const <int>[],
    List<int> aad = const <int>[],
  }) {
    final sink = _DartHmacSink(
      hashAlgorithm,
      Uint8List(hashAlgorithm.blockLengthInBytes),
      hashAlgorithm.toSync().newHashSink(),
      hashAlgorithm.toSync().newHashSink(),
    );
    sink.initializeSync(
      secretKey: secretKeyData,
      nonce: nonce,
    );
    return sink;
  }

  @override
  DartHmac toSync() => this;
}

class _DartHmacSink extends MacSink with DartMacSinkMixin {
  final HashAlgorithm hashAlgorithm;
  final Uint8List _tmp;
  final DartHashSink _innerSink;
  final DartHashSink _outerSink;
  bool _isClosed = false;

  _DartHmacSink(
    this.hashAlgorithm,
    this._tmp,
    this._innerSink,
    this._outerSink,
  );

  @override
  bool get isClosed => _isClosed;

  @override
  Uint8List get macBytes => _outerSink.hashBytes;

  @override
  void addSlice(List<int> chunk, int start, int end, bool isLast) {
    if (isClosed) {
      throw StateError('Sink is closed');
    }
    final innerSink = _innerSink;
    innerSink.addSlice(chunk, start, end, isLast);
    if (isLast) {
      _isClosed = true;
      final innerDigest = innerSink.hashBytes;
      final outerSink = _outerSink;
      outerSink.addSlice(innerDigest, 0, innerDigest.length, true);
    }
  }

  @override
  void initializeSync({
    required SecretKeyData secretKey,
    required List<int> nonce,
    List<int> aad = const [],
  }) {
    if (aad.isNotEmpty) {
      throw ArgumentError.value(
        aad,
        'aad',
        'AAD is not supported by HMAC',
      );
    }
    if (secretKey.bytes.isEmpty) {
      throw ArgumentError.value(
        secretKey,
        'secretKey',
        'Secret key must be non-empty',
      );
    }
    _isClosed = false;
    var hmacKey = secretKey.bytes;
    var eraseKey = false;
    final blockLength = hashAlgorithm.blockLengthInBytes;
    final innerSink = _innerSink;
    innerSink.reset();
    if (hmacKey.length > blockLength) {
      innerSink.addSlice(hmacKey, 0, hmacKey.length, true);
      hmacKey = Uint8List.fromList(innerSink.hashBytes);
      innerSink.reset();
      eraseKey = true;
    }

    // Allocate a temporary buffer
    final tmp = _tmp;

    // Initialize inner sink
    _preparePadding(tmp, hmacKey, 0x36);
    innerSink.addSlice(tmp, 0, tmp.length, false);

    // Erase the temporary buffer
    tmp.fillRange(0, tmp.length, 0);

    // Initialize outer sink
    final outerSink = _outerSink;
    outerSink.reset();
    _preparePadding(tmp, hmacKey, 0x5c);
    outerSink.addSlice(tmp, 0, tmp.length, false);

    // Erase the temporary buffer
    // (safer to not leave the data in memory)
    tmp.fillRange(0, tmp.length, 0);
    if (eraseKey) {
      hmacKey.fillRange(0, hmacKey.length, 0);
    }
  }

  static void _preparePadding(List<int> padding, List<int> key, int byte) {
    for (var i = 0; i < padding.length; i++) {
      padding[i] = i < key.length ? (key[i] ^ byte) : byte;
    }
  }
}
