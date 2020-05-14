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
import 'package:cryptography/utils.dart';
import 'package:meta/meta.dart';

import 'chacha20_impl.dart';

/// _HChaCha20_ ([draft-irtf-cfrg-xchacha](https://tools.ietf.org/html/draft-arciszewski-xchacha-03))
/// key derivation algorithm, which produces a 256-bit secret key from 256-bit
/// secret key and 96-bit nonce.
@visibleForTesting
class HChacha20 {
  const HChacha20();

  SecretKey deriveKeySync({
    @required SecretKey secretKey,
    @required Nonce nonce,
  }) {
    final secretKeyBytes = secretKey.extractSync();
    if (secretKeyBytes.length != 32) {
      throw ArgumentError.value(
        secretKey,
        'secretKey',
        'Must be 32 bytes',
      );
    }
    if (nonce.bytes.length != 16) {
      throw ArgumentError.value(
        nonce,
        'nonce',
        'Must be 16 bytes',
      );
    }
    final nonceBytes = Uint8List.fromList(nonce.bytes);
    final nonceByteData = ByteData.view(nonceBytes.buffer);

    // Initialize state
    final stateInitializer = Chacha20State(const Chacha20());
    stateInitializer.initialize(
      key: secretKeyBytes,
      nonce: Uint8List.view(nonceBytes.buffer, 4, 12),
      keyStreamIndex: 64 * nonceByteData.getUint32(0, Endian.little),
    );

    // Get state
    final state = stateInitializer.initialState;

    // -------------------------------------------------------------------------
    // Step 1: Initialize
    // -------------------------------------------------------------------------
    var v0 = state[0],
        v1 = state[1],
        v2 = state[2],
        v3 = state[3],
        v4 = state[4],
        v5 = state[5],
        v6 = state[6],
        v7 = state[7],
        v8 = state[8],
        v9 = state[9],
        v10 = state[10],
        v11 = state[11],
        v12 = state[12],
        v13 = state[13],
        v14 = state[14],
        v15 = state[15];

    // -------------------------------------------------------------------------
    // Step 2: Do 20 column/diagonal rounds
    //
    // We inlined the 'quarterRound' function because benchmarks showed
    // significant enough difference to non-inlined version.
    // -------------------------------------------------------------------------
    for (var i = 0; i < 10; i++) {
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

    // First 128 bits
    state[0] = v0;
    state[1] = v1;
    state[2] = v2;
    state[3] = v3;

    // Last 128 bits
    state[4] = v12;
    state[5] = v13;
    state[6] = v14;
    state[7] = v15;

    // Change endian
    if (Endian.host != Endian.little) {
      final stateByteData = ByteData.view(state.buffer);
      for (var i = 0; i < 32; i += 4) {
        stateByteData.setUint32(
          i,
          stateByteData.getUint32(i, Endian.host),
          Endian.little,
        );
      }
    }

    return SecretKey(Uint8List.view(
      state.buffer,
      state.offsetInBytes,
      32,
    ));
  }
}
