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
import 'package:meta/meta.dart';

import 'pbkdf2.dart';

class Pbkdf2Impl implements Pbkdf2 {
  @override
  final MacAlgorithm macAlgorithm;

  @override
  final int iterations;

  @override
  final int bits;

  const Pbkdf2Impl({
    @required this.macAlgorithm,
    @required this.iterations,
    @required this.bits,
  })  : assert(macAlgorithm != null),
        assert(iterations >= 1),
        assert(bits >= 64);

  @override
  Future<Uint8List> deriveBits(
    List<int> input, {
    @required Nonce nonce,
  }) async {
    return deriveBitsSync(
      input,
      nonce: nonce,
    );
  }

  @override
  Uint8List deriveBitsSync(
    List<int> password, {
    @required Nonce nonce,
  }) {
    ArgumentError.checkNotNull(password, 'password');
    ArgumentError.checkNotNull(nonce, 'nonce');
    ArgumentError.checkNotNull(bits, 'bits');
    ArgumentError.checkNotNull(iterations, 'iterations');

    final numberOfBytes = (bits + 7) ~/ 8;
    final macLength = macAlgorithm.macLength;
    final result = Uint8List(
      ((numberOfBytes + macLength - 1) ~/ macLength) * macLength,
    );

    // Subsequent blocks
    final secretKey = SecretKey(password);
    final nonceBytes = nonce.bytes;
    final firstInput = Uint8List(nonceBytes.length + 4);
    firstInput.setAll(0, nonceBytes);
    for (var i = 0; i < result.lengthInBytes ~/ macLength; i++) {
      final block = _f(secretKey, firstInput, i);
      result.setAll(macLength * i, block);
    }

    // Return bytes
    if (numberOfBytes == result.lengthInBytes) {
      return result;
    }
    return Uint8List.view(
      result.buffer,
      result.offsetInBytes,
      numberOfBytes,
    );
  }

  List<int> _f(SecretKey secretKey, Uint8List firstInput, int i) {
    // First block has big-endian block index appended
    final fi = firstInput.length - 4;
    final blockIndex = i + 1;
    firstInput[fi] = 0xFF & (blockIndex >> 24);
    firstInput[fi + 1] = 0xFF & (blockIndex >> 16);
    firstInput[fi + 2] = 0xFF & (blockIndex >> 8);
    firstInput[fi + 3] = 0xFF & blockIndex;

    // Calculate first block
    final firstMac = macAlgorithm.calculateMacSync(
      firstInput,
      secretKey: secretKey,
    );
    final block = firstMac.bytes;
    var previous = block;

    // Iterate
    for (var i = 1; i < iterations; i++) {
      // Calculate MAC
      final mac = macAlgorithm.calculateMacSync(
        previous,
        secretKey: secretKey,
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
