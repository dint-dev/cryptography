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

/// [Pbkdf2] implemented in pure Dart.
///
/// For examples and more information about the algorithm, see documentation for
/// the superclass [Pbkdf2].
class DartPbkdf2 extends Pbkdf2 {
  @override
  final MacAlgorithm macAlgorithm;

  @override
  final int iterations;

  @override
  final int bits;

  /// How often to pause to allow the main event loop to handle events.
  final int pauseFrequency;

  /// The duration of a pause every [pauseFrequency] iterations.
  final Duration pausePeriod;

  const DartPbkdf2({
    required this.macAlgorithm,
    required this.iterations,
    required this.bits,
    this.pauseFrequency = 2000,
    this.pausePeriod = const Duration(milliseconds: 1),
  })  : assert(iterations >= 1),
        assert(bits >= 64),
        super.constructor();

  @override
  Future<SecretKey> deriveKey({
    required SecretKey secretKey,
    required List<int> nonce,
  }) async {
    // For performance, we prefer a synchronous MAC algorithm
    final macAlgorithm = this.macAlgorithm.toSync();
    final secretKeyData = await secretKey.extract();

    // Allocate bytes for the output.
    // It must be a multiple of the MAC length.
    final macLength = macAlgorithm.macLength;
    final numberOfBytes = (bits + 7) ~/ 8;
    final result = Uint8List(
      ((numberOfBytes + macLength - 1) ~/ macLength) * macLength,
    );

    // The first input is the nonce + block index
    final nonceAndBlockIndex = Uint8List(nonce.length + 4);
    nonceAndBlockIndex.setAll(0, nonce);
    final firstInput = Uint8List(nonce.length + 4);
    firstInput.setAll(0, nonce);

    final macState = macAlgorithm.newMacSinkSync(
      secretKeyData: secretKeyData,
      nonce: nonce,
    );

    for (var partIndex = 0;
        partIndex < result.lengthInBytes ~/ macLength;
        partIndex++) {
      // First block has big-endian block index appended
      final fi = firstInput.length - 4;
      final blockIndex = partIndex + 1;
      firstInput[fi] = 0xFF & (blockIndex >> 24);
      firstInput[fi + 1] = 0xFF & (blockIndex >> 16);
      firstInput[fi + 2] = 0xFF & (blockIndex >> 8);
      firstInput[fi + 3] = 0xFF & blockIndex;

      // Calculate first block
      final firstMac = macAlgorithm.calculateMacSync(
        firstInput,
        secretKeyData: secretKeyData,
        nonce: nonce,
      );
      final block = Uint8List.fromList(firstMac.bytes);
      final previous = Uint8List(block.length);
      previous.setAll(0, block);

      // Iterate
      for (var i = 1; i < iterations; i++) {
        // Wait a bit to prevent blocking the main event loop
        if (pauseFrequency > 100 &&
            i % pauseFrequency == 0 &&
            pausePeriod.inMicroseconds != 0) {
          await Future.delayed(pausePeriod);
        }
        // Calculate MAC
        macState.initializeSync(
          secretKey: secretKeyData,
          nonce: nonce,
        );
        macState.addSlice(previous, 0, previous.length, true);
        final macBytes = macState.macBytes;

        // XOR with the result
        for (var bi = 0; bi < block.length; bi++) {
          block[bi] ^= macBytes[bi];
        }

        // Update previous block
        for (var i = 0; i < macBytes.length; i++) {
          previous[i] = macBytes[i];
        }
      }
      result.setAll(macLength * partIndex, block);
    }

    // Return bytes
    if (numberOfBytes == result.lengthInBytes) {
      return SecretKey(result);
    }
    return SecretKey(Uint8List.view(
      result.buffer,
      result.offsetInBytes,
      numberOfBytes,
    ));
  }
}
