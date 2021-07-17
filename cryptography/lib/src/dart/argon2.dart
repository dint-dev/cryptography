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

/// [Argon2id] implemented in pure Dart.
class DartArgon2id extends Argon2id {
  @override
  final int parallelism;

  @override
  final int memorySize;

  @override
  final int iterations;

  @override
  final int hashLength;

  const DartArgon2id({
    required this.parallelism,
    required this.memorySize,
    required this.iterations,
    required this.hashLength,
  })  : assert(parallelism >= 1),
        assert(memorySize >= 8 * parallelism),
        assert(iterations >= 1),
        assert(hashLength >= 4),
        super.constructor();

  @override
  Future<SecretKey> deriveKey({
    required SecretKey secretKey,
    required List<int> nonce,
    List<int> k = const <int>[],
    List<int> ad = const <int>[],
  }) async {
    // h0
    final secretKeyBytes = await secretKey.extractBytes();
    final h0Sink = Blake2b().newHashSink();
    _addUint32(h0Sink, parallelism);
    _addUint32(h0Sink, hashLength);
    _addUint32(h0Sink, memorySize);
    _addUint32(h0Sink, iterations);
    _addUint32(h0Sink, version);
    _addSequence(h0Sink, secretKeyBytes);
    _addSequence(h0Sink, nonce);
    _addSequence(h0Sink, k);
    _addSequence(h0Sink, ad);
    h0Sink.close();
    final h0 = (await h0Sink.hash()).bytes;

    final blocks = List<Uint8List?>.filled(parallelism, null);
    blocks[0] = Uint8List.fromList(h0);
    final columnCount = memorySize ~/ parallelism;

    // Initialize parallel lanes
    for (var i = 0; i < parallelism; i++) {
      throw UnimplementedError();
    }

    // First iteration
    for (var i = 0; i < parallelism; i++) {
      for (var j = 2; j < columnCount; j++) {
        throw UnimplementedError();
      }
    }

    // Second and further iterations
    for (var iteration = 1; iteration < iterations; iteration++) {
      for (var i = 0; i < parallelism; i++) {
        for (var j = 0; j < columnCount; j++) {
          throw UnimplementedError();
        }
      }
    }

    // XOR lanes
    final c = blocks[0];
    for (var i = 1; i < blocks.length; i++) {
      final block = blocks[i]!;
      for (var j = 0; j < block.length; j++) {
        c![j] ^= block[j];
      }
    }

    // Final hash
    SecretKey(Uint8List.fromList(await _hash(c!, hashLength)));

    throw UnimplementedError('Does not pass tests yet.');
  }

  /// Variable-length BLAKE2B
  Future<List<int>> _hash(
    List<int> input,
    int size, {
    bool inputIsFirstHash = false,
  }) async {
    final result = Uint8List(size);
    final n = (size + 63) ~/ 64;
    var previousHash = input;
    for (var i = 0; i <= n; i++) {
      late List<int> hash;
      if (i == 0 && inputIsFirstHash) {
        hash = input;
      } else {
        hash = const DartBlake2b().hashSync(previousHash).bytes;
      }
      if (size == 64) {
        return hash;
      }
      result.setAll(64 * i, hash);
      previousHash = hash;
    }
    return result;
  }

  static void _addSequence(HashSink sink, List<int> data) {
    _addUint32(sink, data.length);
    sink.add(data);
  }

  static void _addUint32(HashSink sink, int length) {
    sink.add([
      0xFF & length,
      0xFF & (length >> 8),
      0xFF & (length >> 16),
      0xFF & (length >> 24),
    ]);
  }
}
