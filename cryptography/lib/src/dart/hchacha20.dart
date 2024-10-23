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

import '../_internal/bytes.dart';
import 'chacha20.dart';

/// [Hchacha20] implemented in pure Dart.
///
/// For examples and more information about the algorithm, see documentation for
/// the class [Hchacha20].
class DartHChacha20 extends Hchacha20 {
  const DartHChacha20() : super.constructor();

  @override
  Future<SecretKey> deriveKey({
    required SecretKey secretKey,
    required List<int> nonce,
  }) async {
    final secretKeyData = await secretKey.extract();
    return deriveKeySync(
      secretKeyData: secretKeyData,
      nonce: nonce,
    );
  }

  SecretKeyData deriveKeySync({
    required SecretKeyData secretKeyData,
    required List<int> nonce,
  }) {
    final secretKeyBytes = secretKeyData.bytes;
    if (secretKeyBytes.length != 32) {
      throw ArgumentError.value(
        secretKeyData,
        'secretKey',
        'Must be 32 bytes',
      );
    }
    if (nonce.length != 16) {
      throw ArgumentError.value(
        nonce,
        'nonce',
        'Must be 16 bytes',
      );
    }
    final nonceBytes = Uint8List.fromList(nonce);
    final nonceByteData = ByteData.view(nonceBytes.buffer);

    // Initialize state
    final state = Uint32List(16);
    DartChacha20.initializeChacha(
      state,
      key: secretKeyBytes,
      nonce: Uint8List.view(nonceBytes.buffer, 4, 12),
      keyStreamIndex: 64 * nonceByteData.getUint32(0, Endian.little),
    );

    // Chacha20 without the final addition
    DartChacha20.chachaRounds(state, 0, state, rounds: 20, addAndXor: false);

    // Last 128 bits of the 256-bit key are last 128 bits of the 512-bit state
    state[4] = state[12];
    state[5] = state[13];
    state[6] = state[14];
    state[7] = state[15];

    // Ensure that the integers are little endian
    flipUint32ListEndianUnless(state, Endian.little);

    // Our 256-bit key is ready
    // Copy the first 32 bytes to a new list.
    final copyOfFirst32Bytes = Uint8List.fromList(Uint8List.view(
      state.buffer,
      state.offsetInBytes,
      32,
    ));
    state.fillRange(0, state.length, 0);
    return SecretKeyData(
      copyOfFirst32Bytes,
      overwriteWhenDestroyed: true,
    );
  }
}
