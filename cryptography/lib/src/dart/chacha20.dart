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
import 'package:cryptography/src/utils.dart';

/// [Chacha20] implemented in pure Dart.
///
/// ## Recommendation
/// Usually you should use [Cryptography.chacha20]:
/// ```
/// final cipher = Cryptography.instance.chacha20()
/// ```
class DartChacha20 extends Chacha20 {
  static const int _rounds = 20;

  @override
  final MacAlgorithm macAlgorithm;

  const DartChacha20({
    required this.macAlgorithm,
  }) : super.constructor();

  @override
  Future<List<int>> decrypt(
    SecretBox secretBox, {
    required SecretKey secretKey,
    List<int> aad = const <int>[],
    int keyStreamIndex = 0,
  }) async {
    if (keyStreamIndex < 0) {
      throw ArgumentError.value(
        keyStreamIndex,
        'keyStreamIndex',
        'Must be non-negative',
      );
    }
    if (secretBox.nonce.length != 12) {
      throw ArgumentError.value(
        secretBox,
        'secretBox',
        'Nonce must have 12 bytes',
      );
    }
    final secretKeyData = await secretKey.extract();
    if (secretKeyData.bytes.length != 32) {
      throw ArgumentError.value(
        secretKey,
        'secretKey',
        'Must have 32 bytes',
      );
    }
    final macAlgorithm = this.macAlgorithm;
    if (macAlgorithm is DartChacha20Poly1305AeadMacAlgorithm) {
      if (keyStreamIndex != 0) {
        throw ArgumentError.value(
          keyStreamIndex,
          'keyStreamIndex',
          'Must be zero when AEAD is used',
        );
      }
      keyStreamIndex = 64;
    }

    // Authenticate
    await secretBox.checkMac(
      macAlgorithm: macAlgorithm,
      secretKey: secretKey,
      aad: aad,
    );

    return _xorSync(
      secretBox.cipherText,
      secretKey: secretKeyData,
      nonce: secretBox.nonce,
      aad: aad,
      keyStreamIndex: keyStreamIndex,
    );
  }

  @override
  Future<SecretBox> encrypt(
    List<int> clearText, {
    required SecretKey secretKey,
    List<int>? nonce,
    List<int> aad = const <int>[],
    int keyStreamIndex = 0,
  }) async {
    if (keyStreamIndex < 0) {
      throw ArgumentError.value(
        keyStreamIndex,
        'keyStreamIndex',
        'Must be non-negative',
      );
    }
    nonce ??= newNonce();
    if (nonce.length != 12) {
      throw ArgumentError.value(
        nonce,
        'nonce',
        'Nonce must have 12 bytes',
      );
    }
    final macAlgorithm = this.macAlgorithm;
    if (macAlgorithm is DartChacha20Poly1305AeadMacAlgorithm) {
      if (keyStreamIndex != 0) {
        throw ArgumentError.value(
          keyStreamIndex,
          'keyStreamIndex',
          'Must be zero',
        );
      }
      keyStreamIndex = 64;
    }

    final secretKeyData = await secretKey.extract();
    if (secretKeyData.bytes.length != 32) {
      throw ArgumentError.value(
        secretKey,
        'secretKey',
        'length must be 32 bytes',
      );
    }
    final cipherText = _xorSync(
      clearText,
      secretKey: secretKeyData,
      nonce: nonce,
      aad: aad,
      keyStreamIndex: keyStreamIndex,
    );
    final mac = await macAlgorithm.calculateMac(
      cipherText,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
    );
    return SecretBox(
      cipherText,
      nonce: nonce,
      mac: mac,
    );
  }

  Uint8List _xorSync(
    List<int> clearText, {
    required SecretKeyData secretKey,
    required List<int> nonce,
    List<int> aad = const <int>[],
    int keyStreamIndex = 0,
  }) {
    if (keyStreamIndex < 0) {
      throw ArgumentError.value(keyStreamIndex, 'keyStreamIndex');
    }
    if (secretKey.bytes.length != 32) {
      throw ArgumentError.value(
        secretKey,
        'secretKey',
      );
    }
    if (nonce.length != 12) {
      throw ArgumentError.value(nonce, 'nonce', 'Nonce must have 12 bytes');
    }
    final secretKeyBytes = secretKey.bytes;
    final initialState = Uint32List(16);
    initializeChacha(
      initialState,
      key: secretKeyBytes,
      nonce: nonce,
      keyStreamIndex: keyStreamIndex,
    );
    final skipped = keyStreamIndex % 64;
    final stateAsUint32List = Uint32List(
      (skipped + clearText.length + 63) ~/ 64 * 16,
    );
    final stateAsUint8List = Uint8List.view(stateAsUint32List.buffer);
    stateAsUint8List.setAll(skipped, clearText);
    for (var i = 0; i < stateAsUint32List.length; i += 16) {
      chachaRounds(
        stateAsUint32List,
        i,
        initialState,
        rounds: _rounds,
      );
      initialState[12]++;
    }
    return Uint8List.view(
      stateAsUint32List.buffer,
      skipped,
      clearText.length,
    );
  }

  static void chachaRounds(
    Uint32List state,
    int si,
    Uint32List initialState, {
    required int rounds,
    bool addAndXor = true,
  }) {
    // -------------------------------------------------------------------------
    // Step 1: Initialize
    // -------------------------------------------------------------------------
    var v0 = initialState[0],
        v1 = initialState[1],
        v2 = initialState[2],
        v3 = initialState[3],
        v4 = initialState[4],
        v5 = initialState[5],
        v6 = initialState[6],
        v7 = initialState[7],
        v8 = initialState[8],
        v9 = initialState[9],
        v10 = initialState[10],
        v11 = initialState[11],
        v12 = initialState[12],
        v13 = initialState[13],
        v14 = initialState[14],
        v15 = initialState[15];

    assert(v0 == 0x61707865);
    assert(v1 == 0x3320646e);
    assert(v2 == 0x79622d32);
    assert(v3 == 0x6b206574);

    // -------------------------------------------------------------------------
    // Step 2: Do ROUNDS column/diagonal rounds
    //
    // We inlined the 'quarterRound' function because benchmarks showed
    // significant enough difference to non-inlined version.
    // -------------------------------------------------------------------------
    final roundsDividedByTwo = rounds ~/ 2;
    for (var i = 0; i < roundsDividedByTwo; i++) {
      // -------
      // Columns
      // -------
      v0 = uint32mask & (v0 + v4);
      v12 = rotateLeft32(v12 ^ v0, 16);
      v8 = uint32mask & (v8 + v12);
      v4 = rotateLeft32(v4 ^ v8, 12);
      v0 = uint32mask & (v0 + v4);
      v12 = rotateLeft32(v12 ^ v0, 8);
      v8 = uint32mask & (v8 + v12);
      v4 = rotateLeft32(v4 ^ v8, 7);

      v1 = uint32mask & (v1 + v5);
      v13 = rotateLeft32(v13 ^ v1, 16);
      v9 = uint32mask & (v9 + v13);
      v5 = rotateLeft32(v5 ^ v9, 12);
      v1 = uint32mask & (v1 + v5);
      v13 = rotateLeft32(v13 ^ v1, 8);
      v9 = uint32mask & (v9 + v13);
      v5 = rotateLeft32(v5 ^ v9, 7);

      v2 = uint32mask & (v2 + v6);
      v14 = rotateLeft32(v14 ^ v2, 16);
      v10 = uint32mask & (v10 + v14);
      v6 = rotateLeft32(v6 ^ v10, 12);
      v2 = uint32mask & (v2 + v6);
      v14 = rotateLeft32(v14 ^ v2, 8);
      v10 = uint32mask & (v10 + v14);
      v6 = rotateLeft32(v6 ^ v10, 7);

      v3 = uint32mask & (v3 + v7);
      v15 = rotateLeft32(v15 ^ v3, 16);
      v11 = uint32mask & (v11 + v15);
      v7 = rotateLeft32(v7 ^ v11, 12);
      v3 = uint32mask & (v3 + v7);
      v15 = rotateLeft32(v15 ^ v3, 8);
      v11 = uint32mask & (v11 + v15);
      v7 = rotateLeft32(v7 ^ v11, 7);

      // ---------
      // Diagonals
      // ---------
      v0 = uint32mask & (v0 + v5);
      v15 = rotateLeft32(v15 ^ v0, 16);
      v10 = uint32mask & (v10 + v15);
      v5 = rotateLeft32(v5 ^ v10, 12);
      v0 = uint32mask & (v0 + v5);
      v15 = rotateLeft32(v15 ^ v0, 8);
      v10 = uint32mask & (v10 + v15);
      v5 = rotateLeft32(v5 ^ v10, 7);

      v1 = uint32mask & (v1 + v6);
      v12 = rotateLeft32(v12 ^ v1, 16);
      v11 = uint32mask & (v11 + v12);
      v6 = rotateLeft32(v6 ^ v11, 12);
      v1 = uint32mask & (v1 + v6);
      v12 = rotateLeft32(v12 ^ v1, 8);
      v11 = uint32mask & (v11 + v12);
      v6 = rotateLeft32(v6 ^ v11, 7);

      v2 = uint32mask & (v2 + v7);
      v13 = rotateLeft32(v13 ^ v2, 16);
      v8 = uint32mask & (v8 + v13);
      v7 = rotateLeft32(v7 ^ v8, 12);
      v2 = uint32mask & (v2 + v7);
      v13 = rotateLeft32(v13 ^ v2, 8);
      v8 = uint32mask & (v8 + v13);
      v7 = rotateLeft32(v7 ^ v8, 7);

      v3 = uint32mask & (v3 + v4);
      v14 = rotateLeft32(v14 ^ v3, 16);
      v9 = uint32mask & (v9 + v14);
      v4 = rotateLeft32(v4 ^ v9, 12);
      v3 = uint32mask & (v3 + v4);
      v14 = rotateLeft32(v14 ^ v3, 8);
      v9 = uint32mask & (v9 + v14);
      v4 = rotateLeft32(v4 ^ v9, 7);
    }

    // -------------------------------------------------------------------------
    // Step 3: Addition (not done by Hchacha20)
    // -------------------------------------------------------------------------
    if (addAndXor) {
      state[si + 0] = (0xFFFFFFFF & (v0 + initialState[0])) ^ state[si + 0];
      state[si + 1] = (0xFFFFFFFF & (v1 + initialState[1])) ^ state[si + 1];
      state[si + 2] = (0xFFFFFFFF & (v2 + initialState[2])) ^ state[si + 2];
      state[si + 3] = (0xFFFFFFFF & (v3 + initialState[3])) ^ state[si + 3];
      state[si + 4] = (0xFFFFFFFF & (v4 + initialState[4])) ^ state[si + 4];
      state[si + 5] = (0xFFFFFFFF & (v5 + initialState[5])) ^ state[si + 5];
      state[si + 6] = (0xFFFFFFFF & (v6 + initialState[6])) ^ state[si + 6];
      state[si + 7] = (0xFFFFFFFF & (v7 + initialState[7])) ^ state[si + 7];
      state[si + 8] = (0xFFFFFFFF & (v8 + initialState[8])) ^ state[si + 8];
      state[si + 9] = (0xFFFFFFFF & (v9 + initialState[9])) ^ state[si + 9];
      state[si + 10] = (0xFFFFFFFF & (v10 + initialState[10])) ^ state[si + 10];
      state[si + 11] = (0xFFFFFFFF & (v11 + initialState[11])) ^ state[si + 11];
      state[si + 12] = (0xFFFFFFFF & (v12 + initialState[12])) ^ state[si + 12];
      state[si + 13] = (0xFFFFFFFF & (v13 + initialState[13])) ^ state[si + 13];
      state[si + 14] = (0xFFFFFFFF & (v14 + initialState[14])) ^ state[si + 14];
      state[si + 15] = (0xFFFFFFFF & (v15 + initialState[15])) ^ state[si + 15];
    } else {
      state[si + 0] = v0;
      state[si + 1] = v1;
      state[si + 2] = v2;
      state[si + 3] = v3;
      state[si + 4] = v4;
      state[si + 5] = v5;
      state[si + 6] = v6;
      state[si + 7] = v7;
      state[si + 8] = v8;
      state[si + 9] = v9;
      state[si + 10] = v10;
      state[si + 11] = v11;
      state[si + 12] = v12;
      state[si + 13] = v13;
      state[si + 14] = v14;
      state[si + 15] = v15;
    }
  }

  static void initializeChacha(
    Uint32List state, {
    required List<int> key,
    required List<int> nonce,
    int keyStreamIndex = 0,
  }) {
    if (key.length > 32) {
      throw ArgumentError('Invalid key');
    }
    if (nonce.length > 12) {
      throw ArgumentError('Invalid nonce');
    }
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    final stateByteData = ByteData.view(
      state.buffer,
      state.offsetInBytes,
      64,
    );

    //
    // Key
    //
    var stateBytesIndex = 16;
    for (var i = 0; i < key.length; i++) {
      stateByteData.setUint8(stateBytesIndex, key[i]);
      stateBytesIndex++;
    }

    //
    // Counter
    //
    state[12] = keyStreamIndex ~/ 64;

    //
    // Nonce
    //
    for (var i = 13; i < 16; i++) {
      state[i] = 0;
    }
    stateBytesIndex = 13 * 4;
    for (var i = 0; i < nonce.length; i++) {
      stateByteData.setUint8(stateBytesIndex, nonce[i]);
      stateBytesIndex++;
    }

    // In big endian platforms, convert little endian --> host endian
    if (Endian.host != Endian.little) {
      for (var i = 4; i < 12; i++) {
        state[i] = stateByteData.getUint32(4 * i, Endian.little);
      }
      for (var i = 13; i < 16; i++) {
        state[i] = stateByteData.getUint32(4 * i, Endian.little);
      }
    }
  }
}
