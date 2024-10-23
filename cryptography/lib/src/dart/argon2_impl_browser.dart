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

import 'package:cryptography_plus/dart.dart';

typedef DartArgon2StateImpl = DartArgon2StateImplBrowser;

class DartArgon2StateImplBrowser extends DartArgon2State {
  ByteBuffer? _buffer;

  DartArgon2StateImplBrowser({
    super.version,
    required super.mode,
    required super.parallelism,
    required super.memory,
    required super.iterations,
    required super.hashLength,
    super.maxIsolates,
    super.minBlocksPerSliceForEachIsolate,
    super.blocksPerProcessingChunk,
    ByteBuffer? buffer,
  })  : _buffer = buffer,
        super.constructor();

  @override
  ByteBuffer getByteBuffer() {
    final oldBuffer = _buffer;
    if (oldBuffer != null) {
      return oldBuffer;
    }
    tryReleaseMemory();
    final buffer = Uint32List(256 * blockCount).buffer;
    _buffer = buffer;
    return buffer;
  }

  @override
  void tryReleaseMemory() {
    if (isBufferUsed) {
      return;
    }
    _buffer = null;
    super.tryReleaseMemory();
  }
}
