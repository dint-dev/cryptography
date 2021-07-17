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

/// [Pbkdf2] implemented in pure Dart.
class DartPbkdf2 extends Pbkdf2 {
  @override
  final MacAlgorithm macAlgorithm;

  @override
  final int iterations;

  @override
  final int bits;

  const DartPbkdf2({
    required this.macAlgorithm,
    required this.iterations,
    required this.bits,
  })  : assert(iterations >= 1),
        assert(bits >= 64),
        super.constructor();

  @override
  Future<SecretKey> deriveKey({
    required SecretKey secretKey,
    required List<int> nonce,
  }) async {
    final numberOfBytes = (bits + 7) ~/ 8;
    final macLength = macAlgorithm.macLength;
    final result = Uint8List(
      ((numberOfBytes + macLength - 1) ~/ macLength) * macLength,
    );

    // Subsequent blocks
    final firstInput = Uint8List(nonce.length + 4);
    firstInput.setAll(0, nonce);
    for (var i = 0; i < result.lengthInBytes ~/ macLength; i++) {
      final block = await _f(secretKey, nonce, firstInput, i);
      result.setAll(macLength * i, block);
    }

    // Return bytes
    if (numberOfBytes == result.lengthInBytes) {
      return SecretKey(result);
    }
    return SecretKey(List<int>.unmodifiable(Uint8List.view(
      result.buffer,
      result.offsetInBytes,
      numberOfBytes,
    )));
  }

  Future<List<int>> _f(
    SecretKey secretKey,
    List<int> nonce,
    Uint8List firstInput,
    int i,
  ) async {
    // First block has big-endian block index appended
    final fi = firstInput.length - 4;
    final blockIndex = i + 1;
    firstInput[fi] = 0xFF & (blockIndex >> 24);
    firstInput[fi + 1] = 0xFF & (blockIndex >> 16);
    firstInput[fi + 2] = 0xFF & (blockIndex >> 8);
    firstInput[fi + 3] = 0xFF & blockIndex;

    // Calculate first block
    final firstMac = await macAlgorithm.calculateMac(
      firstInput,
      secretKey: secretKey,
      nonce: nonce,
    );
    final block = Uint8List.fromList(firstMac.bytes);
    List<int> previous = block;

    // Iterate
    for (var i = 1; i < iterations; i++) {
      // Calculate MAC
      final mac = await macAlgorithm.calculateMac(
        previous,
        secretKey: secretKey,
        nonce: nonce,
      );
      final macBytes = mac.bytes;

      // XOR with the result
      for (var bi = 0; bi < block.length; bi++) {
        block[bi] ^= macBytes[bi];
      }

      // Update previous block
      previous = macBytes;
    }
    return block;
  }
}
