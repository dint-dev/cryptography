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

/// Argon2id password hashing function.
///
/// ## Example
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   final argon2 = Argon2id(
///     parallelism: 3,
///     memorySize: 10000000,
///     iterations: 3,
///     hashLength: 32,
///   );
///
///   final hash = await argon2.deriveKey(
///     [1,2,3],
///     salt: [4,5,6],
///   );
///
///   print('hashed password: $hash');
/// }
/// ```
///
class Argon2id {
  final int parallelism;
  final int memorySize;
  final int iterations;
  final int hashLength;
  int get version => 0x13;

  const Argon2id({
    @required this.parallelism,
    @required this.memorySize,
    @required this.iterations,
    @required this.hashLength,
  })  : assert(parallelism >= 1),
        assert(memorySize >= 8 * parallelism),
        assert(iterations >= 1),
        assert(hashLength >= 4);

  Future<Uint8List> deriveKey(
    List<int> password, {
    List<int> salt = const <int>[],
    List<int> key = const <int>[],
    List<int> ad = const <int>[],
  }) async {
    return deriveKeySync(
      password,
      salt: salt,
      key: key,
      ad: ad,
    );
  }

  Uint8List deriveKeySync(
    List<int> password, {
    List<int> salt = const <int>[],
    List<int> key = const <int>[],
    List<int> ad = const <int>[],
  }) {
    ArgumentError.checkNotNull(password, 'password');
    ArgumentError.checkNotNull(salt, 'salt');
    ArgumentError.checkNotNull(key, 'key');
    ArgumentError.checkNotNull(ad, 'ad');

    // h0
    final h0Sink = blake2b.newSink();
    _addUint32(h0Sink, parallelism);
    _addUint32(h0Sink, hashLength);
    _addUint32(h0Sink, memorySize);
    _addUint32(h0Sink, iterations);
    _addUint32(h0Sink, version);
    _addSequence(h0Sink, password);
    _addSequence(h0Sink, salt);
    _addSequence(h0Sink, key);
    _addSequence(h0Sink, ad);
    h0Sink.close();
    final h0 = h0Sink.hash.bytes;

    final blocks = List<Uint8List>(parallelism);
    blocks[0] = h0;
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
      final block = blocks[i];
      for (var j = 0; j < block.length; j++) {
        c[j] ^= block[j];
      }
    }

    // Final hash
    return Uint8List.fromList(_hash(c, hashLength));
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

  /// Variable-length BLAKE2B
  static List<int> _hash(
    List<int> input,
    int size, {
    bool inputIsFirstHash = false,
  }) {
    Uint8List result;
    final n = (size + 63) ~/ 64;
    var previousHash = input;
    for (var i = 0; i <= n; i++) {
      List<int> hash;
      if (i == 0 && inputIsFirstHash) {
        hash = input;
      } else {
        final sink = blake2b.newSink();
        sink.add(previousHash);
        sink.close();
        hash = sink.hash.bytes;
      }
      if (size == 64) {
        return hash;
      }
      result ??= Uint8List(size);
      result.setAll(64 * i, hash);
      previousHash = hash;
    }
    return result;
  }
}
