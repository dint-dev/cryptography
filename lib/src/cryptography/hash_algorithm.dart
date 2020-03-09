// Copyright 2019 Gohilla Ltd (https://gohilla.com).
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

import 'package:cryptography/utils.dart';

/// A result of [HashAlgorithm].
class Hash {
  final List<int> bytes;

  Hash(this.bytes) {
    ArgumentError.checkNotNull(bytes, 'bytes');
  }

  @override
  int get hashCode => const ConstantTimeBytesEquality().hash(bytes);

  @override
  bool operator ==(other) =>
      other is Hash &&
      const ConstantTimeBytesEquality().equals(bytes, other.bytes);

  @override
  String toString() => 'Hash(...)';
}

/// Superclass for hash algorithms.
abstract class HashAlgorithm {
  String get name;

  /// Hash length in bytes.
  int get hashLengthInBytes;

  const HashAlgorithm();

  /// Hashes the data.
  Future<Hash> hash(List<int> input) {
    return Future<Hash>(() => hashSync(input));
  }

  /// Hashes the data.
  Hash hashSync(List<int> input) {
    final sink = newSink();
    sink.add(input);
    return sink.closeSync();
  }

  /// Constructs a new sink for synchronous hashing.
  HashSink newSink();
}

/// A sink created by [HashAlgorithm].
abstract class HashSink implements Sink<List<int>> {
  @override
  Future<Hash> close() {
    return Future<Hash>(() => closeSync());
  }

  Hash closeSync();
}
