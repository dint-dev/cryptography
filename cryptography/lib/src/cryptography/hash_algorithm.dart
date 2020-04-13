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

import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/utils.dart';

/// A result of [HashAlgorithm].
class Hash {
  final List<int> bytes;

  Hash(this.bytes) {
    ArgumentError.checkNotNull(bytes, 'bytes');
  }

  @override
  int get hashCode => constantTimeBytesEquality.hash(bytes);

  @override
  bool operator ==(other) =>
      other is Hash && constantTimeBytesEquality.equals(bytes, other.bytes);

  @override
  String toString() => 'Hash(...)';
}

/// Superclass for hash algorithms.
///
/// Examples:
///   * [blake2s]
///   * [sha1]
///   * [sha224] (SHA2-224)
///   * [sha256] (SHA2-256)
///   * [sha384] (SHA2-384)
///   * [sha512] (SHA2-512)
///
abstract class HashAlgorithm {
  const HashAlgorithm();

  /// The internal block size in bytes.
  int get blockLengthInBytes;

  /// Digest size in bytes.
  int get hashLengthInBytes;

  /// Name of the algorithm for debugging.
  String get name;

  Future<Hash> hash(List<int> input) async {
    return Future<Hash>.value(await hashSync(input));
  }

  Hash hashSync(List<int> data) {
    ArgumentError.checkNotNull(data);
    var sink = newSink();
    sink.add(data);
    sink.close();
    return sink.hash;
  }

  HashSink newSink();

  @override
  String toString() => name;
}

/// Enables calculation of [Hash] for inputs larger than fit in the memory.
abstract class HashSink extends ByteConversionSink {
  /// Result after calling `close()`.
  Hash get hash;

  @override
  void add(List<int> chunk) {
    ArgumentError.checkNotNull(chunk);
    addSlice(chunk, 0, chunk.length, false);
  }
}
