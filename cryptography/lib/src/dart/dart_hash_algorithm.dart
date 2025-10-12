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

import 'dart:async';
import 'dart:typed_data';

import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:meta/meta.dart';

abstract class DartHashAlgorithm extends HashAlgorithm {
  /// Synchronous version of [hash].
  Hash hashSync(List<int> data);

  @override
  DartHashSink newHashSink();

  @override
  DartHashAlgorithm toSync() => this;
}

/// A [HashAlgorithm] that supports synchronous evaluation ([hashSync]).
mixin DartHashAlgorithmMixin implements DartHashAlgorithm {
  @override
  Future<Hash> hash(List<int> input) async {
    return hashSync(input);
  }

  @override
  Hash hashSync(List<int> data) {
    var sink = newHashSink();
    sink.addSlice(data, 0, data.length, true);
    return sink.hashSync();
  }

  @override
  DartHashSink newHashSink();
}

/// A [HashSink] that supports synchronous evaluation ([hashSync]).
abstract class DartHashSink extends HashSink {
  /// Unsafe view at the current hash bytes.
  ///
  /// You must copy the bytes if you want to keep them.
  Uint8List get hashBytes;

  bool get isClosed;

  int get length;

  @override
  void add(List<int> chunk) {
    addSlice(chunk, 0, chunk.length, false);
  }

  @override
  void addSlice(List<int> chunk, int start, int end, bool isLast);

  @override
  void close() {
    addSlice(const [], 0, 0, true);
  }

  @nonVirtual
  @override
  Future<Hash> hash() {
    final result = hashSync();
    return Future<Hash>.value(result);
  }

  /// Computes a hash synchronously (unlike [hash]).
  @nonVirtual
  Hash hashSync() {
    if (!isClosed) {
      throw StateError('Not closed');
    }
    return Hash(Uint8List.fromList(hashBytes));
  }

  void reset();
}
