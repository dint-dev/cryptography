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
import 'dart:ffi';
import 'dart:isolate';
import 'dart:math';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../../dart.dart';

const _mask32 = 0xFFFFFFFF;

typedef DartArgon2StateImpl = DartArgon2StateImplFfi;

class DartArgon2StateImplFfi extends DartArgon2State {
  static final _allocator = calloc;
  static final _finalizer = Finalizer<Pointer>((p0) {
    _allocator.free(p0);
  });
  static const _defaultMaxIsolates = 8;

  ByteBuffer? _buffer;
  int _bufferAddress = 0;

  DartArgon2StateImplFfi({
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
  int get isolateCount {
    var maxIsolates = this.maxIsolates ?? _defaultMaxIsolates;
    if (maxIsolates < 1) {
      return 0;
    }
    maxIsolates = min<int>(parallelism, maxIsolates);
    final blocksPerSlice = blockCount ~/ 4;
    final minBlocksPerSliceForEachIsolate =
        this.minBlocksPerSliceForEachIsolate ?? 200;
    final maxIsolatesGivenMemory =
        blocksPerSlice ~/ minBlocksPerSliceForEachIsolate;
    maxIsolates = min<int>(maxIsolates, maxIsolatesGivenMemory);
    return maxIsolates;
  }

  @override
  void gb(Uint32List data, int a, int b, int c, int d) {
    var v0 = (data[a + 1] << 32) | data[a];
    var v1 = (data[b + 1] << 32) | data[b];
    var v2 = (data[c + 1] << 32) | data[c];
    var v3 = (data[d + 1] << 32) | data[d];

    v0 += v1 + (((_mask32 & v0) * (_mask32 & v1)) << 1);
    v3 ^= v0;
    v3 = (v3 << 32) | (v3 >>> 32);
    v2 += v3 + (((_mask32 & v2) * (_mask32 & v3)) << 1);
    v1 ^= v2;
    v1 = (v1 << 40) | (v1 >>> 24);
    v0 += v1 + (((_mask32 & v0) * (_mask32 & v1)) << 1);
    v3 ^= v0;
    v3 = (v3 << 48) | (v3 >>> 16);
    v2 += v3 + (((_mask32 & v2) * (_mask32 & v3)) << 1);
    v1 ^= v2;
    v1 = (v1 << 1) | (v1 >>> 63);

    data[a] = _mask32 & v0;
    data[a + 1] = v0 >>> 32;
    data[b] = _mask32 & v1;
    data[b + 1] = v1 >>> 32;
    data[c] = _mask32 & v2;
    data[c + 1] = v2 >>> 32;
    data[d] = _mask32 & v3;
    data[d + 1] = v3 >>> 32;
  }

  @override
  ByteBuffer getByteBuffer() {
    final existingBuffer = _buffer;
    if (existingBuffer != null) {
      return existingBuffer;
    }
    if (isolateCount > 0) {
      final pointer = malloc.allocate(1024 * blockCount);
      final buffer =
          pointer.cast<Uint32>().asTypedList(256 * blockCount).buffer;
      _finalizer.attach(buffer, pointer, detach: buffer);
      _buffer = buffer;
      _bufferAddress = pointer.address;
      return buffer;
    } else {
      final buffer = Uint32List(256 * blockCount).buffer;
      _buffer = buffer;
      _bufferAddress = 0;
      return buffer;
    }
  }

  @override
  Future<void> iterate() async {
    final isolateCount = this.isolateCount;
    if (isolateCount < 1 || _bufferAddress == 0) {
      // ignore: invalid_use_of_visible_for_testing_member
      await super.iterate();
      return;
    }
    final isolateFutures = <Future<(Isolate, SendPort)>>[];
    try {
      for (var i = 0; i < isolateCount; i++) {
        final completer = Completer<(Isolate, SendPort)>();
        isolateFutures.add(completer.future);
        final replyPort = ReceivePort();
        Isolate.spawn(
          _segmentProcessingEntryPoint,
          replyPort.sendPort,
          debugName: 'argon2-$i',
        ).then((isolate) {
          replyPort.first.then((sendPort) {
            if (sendPort is! SendPort) {
              completer.completeError(ArgumentError());
            } else {
              completer.complete((isolate, sendPort));
            }
            replyPort.close();
          }, onError: (error, stackTrace) {
            completer.completeError(error, stackTrace);
            replyPort.close();
          });
        }, onError: (error, stackTrace) {
          completer.completeError(error, stackTrace);
          replyPort.close();
        });
      }
      final isolates = await Future.wait(isolateFutures);

      //
      // For each iteration
      //
      for (var iteration = 0; iteration < iterations; iteration++) {
        //
        // For each of the four slices
        //
        for (var slice = 0; slice < 4; slice++) {
          //
          // Schedule N segments to M isolates
          //
          final futures = <Future>[];
          var isolateIndex = 0;
          final segmentCountPerIsolate =
              max<int>(1, parallelism ~/ isolateCount);
          var remainderLanes =
              parallelism - segmentCountPerIsolate * isolates.length;
          for (var lane = 0; lane < parallelism;) {
            // Choose how many lanes the isolate will process.
            var laneCount = segmentCountPerIsolate;
            if (remainderLanes > 0) {
              laneCount++;
              remainderLanes--;
            }
            assert(laneCount >= 1);
            assert(lane + laneCount <= parallelism);

            // Send the task to the isolate.
            final (_, sendPort) = isolates[isolateIndex];
            final future = _sendSegmentsToIsolate(
              sendPort: sendPort,
              iteration: iteration,
              slice: slice,
              lane: lane,
              laneCount: laneCount,
            );
            futures.add(future);

            // Increment variables
            lane += laneCount;
            isolateIndex++;
          }

          // Wait for all segments in the slice to be processes
          // (before moving to the next slice).
          await Future.wait(futures);
        }
      }
    } finally {
      // Kill all isolates.
      for (var isolateFuture in isolateFutures) {
        isolateFuture.then((result) {
          final (isolate, _) = result;
          isolate.kill(priority: Isolate.immediate);
        });
      }
    }
  }

  @override
  int referredBlockIndexZZ(int j1, int candidatesLength) {
    final x = (j1 * j1) >>> 32;
    final y = (candidatesLength * x) >>> 32;
    return y % candidatesLength;
  }

  @override
  void tryReleaseMemory() {
    if (isBufferUsed) {
      throw StateError('$runtimeType is active');
    }
    final buffer = _buffer;
    final bufferAddress = _bufferAddress;

    // Free memory immediately rather than waiting for the finalizer to be
    // called.
    if (buffer != null && bufferAddress != 0) {
      _finalizer.detach(buffer);
      _allocator.free(Pointer<Uint8>.fromAddress(bufferAddress));
    }

    _buffer = null;
    _bufferAddress = 0;
    super.tryReleaseMemory();
  }

  Future<void> _sendSegmentsToIsolate({
    required SendPort sendPort,
    required int iteration,
    required int slice,
    required int lane,
    required int laneCount,
  }) async {
    final receivePort = ReceivePort();
    sendPort.send([
      receivePort.sendPort,
      version,
      mode.index,
      memory,
      parallelism,
      iterations,
      hashLength,
      _bufferAddress,
      iteration,
      slice,
      lane,
      laneCount,
    ]);
    final error = await receivePort.first.timeout(const Duration(seconds: 10),
        onTimeout: () {
      throw StateError('Segment processing timeout');
    });
    if (error != null) {
      throw error;
    }
  }

  static void _segmentProcessingEntryPoint(SendPort replyPort) {
    final receivePort = ReceivePort();
    receivePort.listen((message) async {
      final replyPort = message[0] as SendPort;
      try {
        if (message is! List) {
          throw ArgumentError();
        }
        final version = message[1] as int;
        final mode = DartArgon2Mode.values[message[2] as int];
        final memory = message[3] as int;
        final parallelism = message[4] as int;
        final iterations = message[5] as int;
        final hashLength = message[6] as int;
        final bufferAddress = message[7] as int;
        final iteration = message[8] as int;
        final slice = message[9] as int;
        final lanesStart = message[10] as int;
        final lanesLength = message[11] as int;
        final pointer = Pointer<Uint8>.fromAddress(bufferAddress);
        final buffer = pointer.asTypedList(1024 * memory).buffer;
        final state = DartArgon2StateImplFfi(
          version: version,
          mode: mode,
          memory: memory,
          parallelism: parallelism,
          iterations: iterations,
          hashLength: hashLength,
          buffer: buffer,
          maxIsolates: 0, // Do not create isolates
          blocksPerProcessingChunk: -1, // No need to give time to other tasks
        );
        assert(lanesLength >= 1);
        for (var i = 0; i < lanesLength; i++) {
          // ignore: invalid_use_of_visible_for_testing_member
          await state.processSegment(
            iteration: iteration,
            slice: slice,
            lane: lanesStart + i,
          );
        }
        replyPort.send(null);
      } catch (error) {
        replyPort.send('Error: $error');
      }
    });
    replyPort.send(receivePort.sendPort);
  }
}
