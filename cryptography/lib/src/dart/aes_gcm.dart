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
import 'package:cryptography_plus/src/dart/dart_mac_algorithm.dart';
import 'package:meta/meta.dart';

import '../../helpers.dart';
import 'aes_impl.dart';

const _bit32 = 0x100 * 0x100 * 0x100 * 0x100;

int _uint32ChangeEndian(int v) {
// We mask with 0xFFFFFFFF to ensure the compiler recognizes the value will
// be small enough to be a 'mint'.
  return (0xFFFFFFFF & ((0xFF & v) << 24)) |
      (0xFFFFFF & ((0xFF & (v >> 8)) << 16)) |
      (0xFFFF & ((0xFF & (v >> 16)) << 8)) |
      (0xFF & (v >> 24));
}

/// [AesGcm] implemented in pure Dart.
///
/// For examples and more information about the algorithm, see documentation for
/// the class [AesGcm].
//
// The implementation was written based on the original specification:
//   https://csrc.nist.gov/publications/detail/sp/800-38d/final
//
class DartAesGcm extends AesGcm with DartAesMixin {
  @override
  final int nonceLength;

  @override
  final int secretKeyLength;

  DartAesGcm({
    this.secretKeyLength = 32,
    this.nonceLength = AesGcm.defaultNonceLength,
    super.random,
  })  : assert(secretKeyLength == 16 ||
            secretKeyLength == 24 ||
            secretKeyLength == 32),
        assert(nonceLength >= 4),
        super.constructor() {
    if (Endian.host != Endian.little) {
      throw StateError('BigEndian systems are unsupported');
    }
  }

  DartAesGcm.with128bits({
    int nonceLength = AesGcm.defaultNonceLength,
  }) : this(secretKeyLength: 16, nonceLength: nonceLength);

  DartAesGcm.with192bits({
    int nonceLength = AesGcm.defaultNonceLength,
  }) : this(secretKeyLength: 24, nonceLength: nonceLength);

  DartAesGcm.with256bits({
    int nonceLength = AesGcm.defaultNonceLength,
  }) : this(secretKeyLength: 32, nonceLength: nonceLength);

  @nonVirtual
  @override
  Future<List<int>> decrypt(
    SecretBox secretBox, {
    required SecretKey secretKey,
    List<int> aad = const <int>[],
    Uint8List? possibleBuffer,
  }) async {
    final secretKeyData = await secretKey.extract();
    return decryptSync(
      secretBox,
      secretKeyData: secretKeyData,
      aad: aad,
    );
  }

  List<int> decryptSync(
    SecretBox secretBox, {
    required SecretKeyData secretKeyData,
    List<int> aad = const <int>[],
  }) {
    final actualSecretKeyLength = secretKeyData.bytes.length;
    final expectedSecretKeyLength = secretKeyLength;
    if (actualSecretKeyLength != expectedSecretKeyLength) {
      throw ArgumentError.value(
        secretKeyData,
        'secretKeyData',
        'Expected $expectedSecretKeyLength bytes, got $actualSecretKeyLength bytes',
      );
    }
    final nonce = secretBox.nonce;

    final expandedKey = aesExpandKeyForEncrypting(secretKeyData);

    final h = Uint32List(4);
    aesEncryptBlock(h, 0, h, 0, expandedKey);
    h[0] = _uint32ChangeEndian(h[0]);
    h[1] = _uint32ChangeEndian(h[1]);
    h[2] = _uint32ChangeEndian(h[2]);
    h[3] = _uint32ChangeEndian(h[3]);

    // Calculate initial nonce
    var stateBytes = _nonceToBlock(h: h, nonce: nonce);
    var state = Uint32List.view(stateBytes.buffer);

    // Calculate MAC
    final cipherText = secretBox.cipherText;
    final mac = secretBox.mac;
    final calculatedMac = const DartGcm()._calculateMacSync(
      cipherText,
      aad: aad,
      expandedKey: expandedKey,
      h: h,
      precounterBlock: state,
    );

    // Check MAC is correct
    if (calculatedMac != mac) {
      throw SecretBoxAuthenticationError();
    }

    // Increment nonce
    bytesIncrementBigEndian(stateBytes, 1);

    // Allocate output bytes
    final blockCount = (cipherText.length + 31) ~/ 16;
    final keyStream = Uint32List(blockCount * 4);

    // For each key stream block
    for (var i = 0; i < keyStream.length; i += 4) {
      // Encrypt state.
      aesEncryptBlock(keyStream, i, state, 0, expandedKey);

      // Increment state.
      bytesIncrementBigEndian(stateBytes, 1);
    }

    // clearText = keyStream ^ ciphertext`
    final clearText = Uint8List.view(
      keyStream.buffer,
      keyStream.offsetInBytes,
      cipherText.length,
    );
    for (var i = 0; i < cipherText.length; i++) {
      clearText[i] ^= cipherText[i];
    }
    return clearText;
  }

  @nonVirtual
  @override
  Future<SecretBox> encrypt(
    List<int> clearText, {
    required SecretKey secretKey,
    List<int>? nonce,
    List<int> aad = const <int>[],
    Uint8List? possibleBuffer,
  }) async {
    final secretKeyData = await secretKey.extract();
    return encryptSync(
      clearText,
      secretKeyData: secretKeyData,
      nonce: nonce,
      aad: aad,
    );
  } // = 1<<32

  SecretBox encryptSync(
    List<int> clearText, {
    required SecretKeyData secretKeyData,
    List<int>? nonce,
    List<int> aad = const <int>[],
  }) {
    final actualSecretKeyLength = secretKeyData.bytes.length;
    final expectedSecretKeyLength = secretKeyLength;
    if (actualSecretKeyLength != expectedSecretKeyLength) {
      throw ArgumentError.value(
        secretKeyData,
        'secretKeyData',
        'Expected $expectedSecretKeyLength bytes, got $actualSecretKeyLength bytes',
      );
    }
    nonce ??= newNonce();
    final expandedKey = aesExpandKeyForEncrypting(secretKeyData);

    // `h` = AES(zero_block, key)
    final h = Uint32List(4);
    aesEncryptBlock(h, 0, h, 0, expandedKey);
    h[0] = _uint32ChangeEndian(h[0]);
    h[1] = _uint32ChangeEndian(h[1]);
    h[2] = _uint32ChangeEndian(h[2]);
    h[3] = _uint32ChangeEndian(h[3]);

    // Calculate initial nonce
    var stateBytes = _nonceToBlock(h: h, nonce: nonce);
    var state = Uint32List.view(stateBytes.buffer);

    // Memorize the state of the first block for calculating MAC later.
    final stateOfFirstBlock = Uint32List.fromList(state);

    // Increment nonce
    bytesIncrementBigEndian(stateBytes, 1);

    // Allocate space for output bytes + 128 bit hash
    final blockCount = (clearText.length + 15) ~/ 16;
    final keyStream = Uint32List((blockCount + 1) * 4);

    // For each block
    for (var i = 0; i < keyStream.length; i += 4) {
      // Encrypt state.
      aesEncryptBlock(keyStream, i, state, 0, expandedKey);

      // Increment state.
      bytesIncrementBigEndian(stateBytes, 1);
    }

    // cipherText = keyStream ^ clearText
    final cipherText = Uint8List.view(
      keyStream.buffer,
      keyStream.offsetInBytes,
      clearText.length,
    );
    for (var i = 0; i < clearText.length; i++) {
      cipherText[i] ^= clearText[i];
    }

    // Calculate MAC
    final mac = const DartGcm()._calculateMacSync(
      cipherText,
      aad: aad,
      expandedKey: expandedKey,
      h: h,
      precounterBlock: stateOfFirstBlock,
    );

    return SecretBox(cipherText, nonce: nonce, mac: mac);
  }

  @override
  DartAesGcm toSync() {
    return this;
  }

  static void _ghash(Uint32List result, Uint32List h, List<int> data) {
    final ghashState = ByteData(16);
    ghashState.setUint32(0, 0);
    ghashState.setUint32(4, 0);
    ghashState.setUint32(8, 0);
    ghashState.setUint32(12, 0);

    // Allocate one block
    var x0 = _uint32ChangeEndian(result[0]);
    var x1 = _uint32ChangeEndian(result[1]);
    var x2 = _uint32ChangeEndian(result[2]);
    var x3 = _uint32ChangeEndian(result[3]);
    final h0 = h[0];
    final h1 = h[1];
    final h2 = h[2];
    final h3 = h[3];

    // For each
    for (var i = 0; i < data.length; i += 16) {
      if (i + 16 <= data.length) {
        for (var j = 0; j < 16; j++) {
          ghashState.setUint8(j, data[i + j]);
        }
      } else {
        ghashState.setUint32(0, 0);
        ghashState.setUint32(4, 0);
        ghashState.setUint32(8, 0);
        ghashState.setUint32(12, 0);
        final n = data.length % 16;
        for (var j = 0; j < n; j++) {
          ghashState.setUint8(j, data[i + j]);
        }
      }

      // result ^= x_i
      x0 ^= ghashState.getUint32(0, Endian.big);
      x1 ^= ghashState.getUint32(4, Endian.big);
      x2 ^= ghashState.getUint32(8, Endian.big);
      x3 ^= ghashState.getUint32(12, Endian.big);

      var z0 = 0;
      var z1 = 0;
      var z2 = 0;
      var z3 = 0;

      // TODO: Improve performance by not doing endian conversions.
      var hi = h0;
      for (var i = 0; i < 128; i++) {
        // Get bit `i` of `h`
        if (i % 32 == 0 && i != 0) {
          if (i == 32) {
            hi = h1;
          } else if (i == 64) {
            hi = h2;
          } else {
            hi = h3;
          }
        }
        final hBit = hi & (1 << (31 - i % 32));
        if (hBit != 0) {
          z0 ^= x0;
          z1 ^= x1;
          z2 ^= x2;
          z3 ^= x3;
        }

        var carry = 0;
        final tmp0 = x0;
        x0 = carry | (tmp0 >> 1);
        carry = 0xFFFFFFFF & ((0x1 & tmp0) << 31);

        final tmp1 = x1;
        x1 = carry | (tmp1 >> 1);
        carry = 0xFFFFFFFF & ((0x1 & tmp1) << 31);

        final tmp2 = (x2);
        x2 = carry | (tmp2 >> 1);
        carry = 0xFFFFFFFF & ((0x1 & tmp2) << 31);

        final tmp3 = (x3);
        x3 = carry | (tmp3 >> 1);
        carry = 0xFFFFFFFF & ((0x1 & tmp3) << 31);

        if (carry != 0) {
          x0 ^= 0xe1000000;
        }
      }
      x0 = z0;
      x1 = z1;
      x2 = z2;
      x3 = z3;
    }
    result[0] = _uint32ChangeEndian(x0);
    result[1] = _uint32ChangeEndian(x1);
    result[2] = _uint32ChangeEndian(x2);
    result[3] = _uint32ChangeEndian(x3);
  }

  /// Returns nonce as 128-bit block
  static Uint8List _nonceToBlock({
    required Uint32List h,
    required List<int> nonce,
  }) {
    final nonceLength = nonce.length;
    if (nonceLength == 12) {
      // If the nonce has exactly 12 bytes,
      // we just write it directly.
      final nonceBytes = Uint8List(16);
      nonceBytes.setAll(0, nonce);
      nonceBytes[nonceBytes.length - 1] = 1;
      return nonceBytes;
    }
    // Otherwise we take a hash of:
    //   nonce + padding
    //   padding (8 bytes)
    //   length of nonce in bits (uint64)
    final suffixByteData = ByteData(16);
    suffixByteData.setUint32(8, (8 * nonceLength) ~/ _bit32, Endian.big);
    suffixByteData.setUint32(12, (8 * nonceLength) % _bit32, Endian.big);
    final suffixBytes = Uint8List.view(suffixByteData.buffer);
    final result = Uint32List(4);
    _ghash(result, h, nonce);
    _ghash(result, h, suffixBytes);
    return Uint8List.view(result.buffer);
  }
}

/// [AesGcm] MAC algorithm implemented in pure Dart.
class DartGcm extends MacAlgorithm with DartMacAlgorithmMixin {
  const DartGcm();

  @override
  int get macLength => 16;

  @override
  bool get supportsAad => true;

  @override
  Future<Mac> calculateMac(
    List<int> bytes, {
    required SecretKey secretKey,
    List<int> nonce = const <int>[],
    List<int> aad = const <int>[],
  }) {
    throw UnsupportedError(
      'AES-GCM MAC algorithm can NOT be called separately.',
    );
  }

  @override
  DartMacSinkMixin newMacSinkSync(
      {required SecretKeyData secretKeyData,
      List<int> nonce = const <int>[],
      List<int> aad = const <int>[]}) {
    throw UnimplementedError();
  }

  @override
  String toString() => 'DartGcm()';

  @override
  DartGcm toSync() {
    return this;
  }

  Mac _calculateMacSync(
    List<int> cipherText, {
    required Uint32List precounterBlock,
    required Uint32List h,
    required Uint32List expandedKey,
    required List<int> aad,
  }) {
    // We XOR hashes for:
    //   * AAD + padding until 16-byte aligned
    //   * Ciphertext + padding until 16-byte aligned
    //   * Big endian uint64: AAD length in bits
    //   * Big endian uint64: Ciphertext length in bits
    final mac = Uint32List(4);
    DartAesGcm._ghash(mac, h, aad);
    DartAesGcm._ghash(mac, h, cipherText);
    final aadBits = 8 * aad.length;
    final cipherTextBits = 8 * cipherText.length;
    // For big numbers to work in browsers, we use some tricks.
    final macDataByteData = ByteData(16);
    macDataByteData.setUint32(0, aadBits ~/ _bit32, Endian.big);
    macDataByteData.setUint32(4, aadBits % _bit32, Endian.big);
    macDataByteData.setUint32(8, cipherTextBits ~/ _bit32, Endian.big);
    macDataByteData.setUint32(12, cipherTextBits % _bit32, Endian.big);
    DartAesGcm._ghash(mac, h, Uint8List.view(macDataByteData.buffer));

    // Finally we XOR with AES(precounter, secretKey)
    final encryptedPrecounter = Uint32List(4);
    aesEncryptBlock(encryptedPrecounter, 0, precounterBlock, 0, expandedKey);
    mac[0] ^= encryptedPrecounter[0];
    mac[1] ^= encryptedPrecounter[1];
    mac[2] ^= encryptedPrecounter[2];
    mac[3] ^= encryptedPrecounter[3];

    return Mac(Uint8List.view(mac.buffer));
  }
}
