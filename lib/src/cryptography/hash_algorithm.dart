// Copyright 2019 Gohilla (opensource@gohilla.com).
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

import 'package:cryptography/math.dart';
import 'package:meta/meta.dart';

abstract class HashAlgorithm {
  const HashAlgorithm({@required this.blockLength});

  const factory HashAlgorithm.fromSinkFactory(HashSink newSink(),
      {@required int blockLength}) = _HashAlgorithm;

  /// Block length in bytes.
  final int blockLength;

  /// Hashes the data.
  Hash hash(List<int> input) {
    final sink = newSink();
    sink.add(input);
    return sink.close();
  }

  /// Constructs a new sink for synchronous hashing.
  HashSink newSink();
}

class _HashAlgorithm extends HashAlgorithm {
  final HashSink Function() _newSink;

  const _HashAlgorithm(this._newSink, {@required int blockLength})
      : super(blockLength: blockLength);

  @override
  HashSink newSink() {
    return _newSink();
  }
}

abstract class HashSink implements Sink<List<int>> {
  @override
  void add(List<int> data);

  @override
  Hash close();
}

class Hash {
  final List<int> bytes;

  Hash(this.bytes) {
    ArgumentError.checkNotNull(bytes, "bytes");
  }

  @override
  operator ==(other) =>
      other is Hash &&
      const ConstantTimeBytesEquality().equals(bytes, other.bytes);

  @override
  int get hashCode => const ConstantTimeBytesEquality().hash(bytes);

  @override
  String toString() => "Hash(...)";
}
