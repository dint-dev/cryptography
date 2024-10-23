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
import 'package:cryptography_plus/src/utils.dart';
import 'package:meta/meta.dart';

import '../../dart.dart';

/// A pure Dart implementation of _AEAD_CHACHA20_POLY1305_ message
/// authentication.
///
/// Used by [Chacha20.poly1305Aead] and [Xchacha20.poly1305Aead].
class DartChacha20Poly1305AeadMacAlgorithm extends MacAlgorithm
    with DartMacAlgorithmMixin {
  /// Constructs _AEAD_CHACHA20_POLY1305_.
  ///
  /// Optional parameter [chacha20] defines the non-AEAD _ChaCha20_
  /// implementation used by this algorithm. The default is [DartChacha20].
  ///
  /// Optional parameter [poly1305] defines the _Poly1305_ implementation used
  /// by this algorithm. The default is [DartPoly1305].
  ///
  /// ## Example
  /// ```dart
  /// import 'package:cryptography_plus/dart.dart';
  ///
  /// void main() {
  ///   final algorithm = DartChacha20Poly1305AeadMacAlgorithm();
  ///   // ...
  /// }
  /// ```
  @literal
  const DartChacha20Poly1305AeadMacAlgorithm({
    @Deprecated('Do not use') Chacha20? chacha20,
    @Deprecated('Do not use') Poly1305? poly1305,
    @Deprecated('Do not use') bool useStaticBuffer = false,
  });

  @override
  int get hashCode => (DartChacha20Poly1305AeadMacAlgorithm).hashCode;

  // The first block of the ChaCha20 stream is used as the Poly1305 key.
  @override
  int get keyStreamUsed => 64;

  @override
  int get macLength => 16;

  @override
  bool get supportsAad => true;

  @override
  bool operator ==(other) => other is DartChacha20Poly1305AeadMacAlgorithm;

  @override
  DartMacSinkMixin newMacSinkSync({
    required SecretKeyData secretKeyData,
    List<int> nonce = const <int>[],
    List<int> aad = const <int>[],
  }) {
    final sink = DartChacha20Poly1305AeadMacAlgorithmSink();
    sink.initializeSync(
      secretKey: secretKeyData,
      nonce: nonce,
      aad: aad,
    );
    return sink;
  }

  @override
  DartChacha20Poly1305AeadMacAlgorithm toSync() {
    return this;
  }
}

class DartChacha20Poly1305AeadMacAlgorithmSink extends DartPoly1305Sink {
  int _aadLength = 0;
  final _tmpAsByteData = ByteData(16);
  late final _tmpAsUint8List = Uint8List.view(_tmpAsByteData.buffer);
  final _chacha20State = const DartChacha20(
    macAlgorithm: MacAlgorithm.empty,
  ).newState();

  @override
  void afterData() {
    // Length without the initial AAD.
    final aadLength = _aadLength;
    final dataLength = length - (aadLength + 15) ~/ 16 * 16;

    final lengthRem = dataLength % 16;
    if (lengthRem != 0) {
      // Add padding until 16-byte aligned
      final paddingLength = 16 - lengthRem;
      _tmpAsUint8List.fillRange(0, paddingLength, 0);
      addSlice(_tmpAsUint8List, 0, paddingLength, false);
    }
    final tmpByteData = _tmpAsByteData;
    tmpByteData.setUint32(0, 0);
    tmpByteData.setUint32(4, 0);
    tmpByteData.setUint32(8, 0);
    tmpByteData.setUint32(12, 0);

    // Add 16-byte footer.
    // We can't use setUint64() because it's not supported in the browsers.
    tmpByteData.setUint32(
      0,
      uint32mask & aadLength,
      Endian.little,
    );
    tmpByteData.setUint32(
      4,
      aadLength ~/ (uint32mask + 1),
      Endian.little,
    );
    tmpByteData.setUint32(
      8,
      uint32mask & dataLength,
      Endian.little,
    );
    tmpByteData.setUint32(
      12,
      dataLength ~/ (uint32mask + 1),
      Endian.little,
    );
    add(_tmpAsUint8List);
    _aadLength = 0;
  }

  @override
  void beforeData({
    required SecretKeyData secretKey,
    required List<int> nonce,
    List<int> aad = const [],
  }) {
    // Add Additional Authenticated Data (AAD)
    final aadLength = aad.length;
    _aadLength = aadLength;
    if (aadLength != 0) {
      add(aad);

      // Add padding until 16-byte aligned
      final rem = aad.length % 16;
      if (rem != 0) {
        // Fill `tmp` with zeroes
        final tmp = _tmpAsByteData;
        tmp.setUint32(0, 0);
        tmp.setUint32(4, 0);
        tmp.setUint32(8, 0);
        tmp.setUint32(12, 0);
        final paddingLength = 16 - rem;
        addSlice(_tmpAsUint8List, 0, paddingLength, false);
      }
    }

    // Initialize ChaCha20 initial state
    super.beforeData(
      secretKey: secretKey,
      nonce: nonce,
      aad: const [],
    );
  }

  /// Used by [DartXchacha20Poly1305AeadMacAlgorithmSink].
  SecretKeyData deriveSecretKey({
    required SecretKeyData secretKey,
    required List<int> nonce,
  }) {
    if (nonce.length != 12) {
      throw ArgumentError.value(
        nonce,
        'nonce',
        'Nonce must have 12 bytes, got ${nonce.length} bytes',
      );
    }
    List<int> newSecretKey = Uint8List(32);
    _chacha20State.initializeSync(
      isEncrypting: true,
      secretKey: secretKey,
      nonce: nonce,
    );
    newSecretKey = _chacha20State.convertSync(
      newSecretKey,
      possibleBuffer: newSecretKey is Uint8List ? newSecretKey : null,
    );
    return SecretKeyData(
      newSecretKey,
      overwriteWhenDestroyed: true,
    );
  }

  @override
  void initializeSync({
    required SecretKeyData secretKey,
    required List<int> nonce,
    List<int> aad = const [],
  }) {
    _aadLength = 0;
    _tmpAsUint8List.fillRange(0, _tmpAsUint8List.length, 0);
    secretKey = deriveSecretKey(
      secretKey: secretKey,
      nonce: nonce,
    );
    super.initializeSync(
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
    );
  }
}
