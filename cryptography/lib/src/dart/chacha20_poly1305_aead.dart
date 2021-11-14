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
import 'package:cryptography/src/utils.dart';

/// A pure Dart implementation of _AEAD_CHACHA20_POLY1305_ message
/// authentication.
///
/// Used by [Chacha20.poly1305Aead] and [Xchacha20.poly1305Aead].
class DartChacha20Poly1305AeadMacAlgorithm extends MacAlgorithm {
  static final _tmpByteData = ByteData(16);
  static final _tmpUint8List = Uint8List.view(_tmpByteData.buffer);

  final StreamingCipher _chacha20;
  final Poly1305 _poly1305;
  final bool _useStaticBuffer;

  DartChacha20Poly1305AeadMacAlgorithm({
    Chacha20? chacha20,
    Poly1305? poly1305,
    bool useStaticBuffer = false,
  })  : _chacha20 = chacha20 ?? Chacha20(macAlgorithm: MacAlgorithm.empty),
        _poly1305 = poly1305 ?? Poly1305(),
        _useStaticBuffer = useStaticBuffer;

  @override
  int get hashCode => (DartChacha20Poly1305AeadMacAlgorithm).hashCode;

  @override
  int get macLength => 16;

  @override
  bool get supportsAad => true;

  @override
  bool operator ==(other) => other is DartChacha20Poly1305AeadMacAlgorithm;

  @override
  Future<Mac> calculateMac(
    List<int> bytes, {
    required SecretKey secretKey,
    List<int> nonce = const <int>[],
    List<int> aad = const <int>[],
  }) async {
    final secretKeyForPoly1305 = await _poly1305SecretKeyFromChacha20(
      secretKey: secretKey,
      nonce: nonce,
    );
    final sink = await _poly1305.newMacSink(
      secretKey: secretKeyForPoly1305,
    );

    var length = 0;

    late ByteData tmpByteData;
    late Uint8List tmpUint8List;
    if (_useStaticBuffer) {
      tmpByteData = _tmpByteData;
      tmpUint8List = _tmpUint8List;
    } else {
      tmpByteData = ByteData(16);
      tmpUint8List = Uint8List.view(tmpByteData.buffer);
    }
    tmpByteData.setUint32(0, 0);
    tmpByteData.setUint32(4, 0);
    tmpByteData.setUint32(8, 0);
    tmpByteData.setUint32(12, 0);

    // Add Additional Authenticated Data (AAD)
    final aadLength = aad.length;
    if (aadLength != 0) {
      sink.add(aad);
      length += aad.length;

      final rem = length % 16;
      if (rem != 0) {
        // Add padding
        final paddingLength = 16 - rem;
        sink.add(tmpUint8List.sublist(0, paddingLength));
        length += paddingLength;
      }
    }

    // Add cipherText
    sink.add(bytes);
    length += bytes.length;
    final rem = length % 16;
    if (rem != 0) {
      // Add padding
      final paddingLength = 16 - rem;
      sink.add(tmpUint8List.sublist(0, paddingLength));
      length += paddingLength;
    }

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
      uint32mask & bytes.length,
      Endian.little,
    );
    tmpByteData.setUint32(
      12,
      bytes.length ~/ (uint32mask + 1),
      Endian.little,
    );
    sink.add(tmpUint8List);

    // Reset the static buffer.
    tmpByteData.setUint32(0, 0);
    tmpByteData.setUint32(4, 0);
    tmpByteData.setUint32(8, 0);
    tmpByteData.setUint32(12, 0);

    // Return MAC
    sink.close();

    return sink.mac();
  }

  /// A function needed by _AEAD_CHACHA20_POLY1305_.
  Future<SecretKeyData> _poly1305SecretKeyFromChacha20({
    required SecretKey secretKey,
    required List<int> nonce,
  }) async {
    if (nonce.length != 12) {
      throw ArgumentError.value(
        nonce,
        'nonce',
        'Nonce must have 12 bytes, got ${nonce.length} bytes',
      );
    }
    final secretBox = await _chacha20.encrypt(
      Uint8List(32),
      secretKey: secretKey,
      nonce: nonce,
    );
    return SecretKeyData(secretBox.cipherText);
  }
}
