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
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:cryptography_plus/dart.dart';
import 'package:cryptography_plus/src/dart/_helpers.dart';
import 'package:cryptography_plus/src/dart/argon2_impl_browser.dart'
    if (dart.library.ffi) 'package:cryptography_plus/src/dart/argon2_impl_vm.dart';
import 'package:meta/meta.dart';

const _bit32 = 0x100000000;
const _blake2bSize = 64;
const _mask32 = 0xFFFFFFFF;

/// 256 x 32 bits
typedef _Block = Uint32List;

/// [Argon2id] ([RFC 9106](https://datatracker.ietf.org/doc/rfc9106/))
/// implemented in pure Dart.
///
/// The implementation uses [DartArgon2State]. You can use the state object
/// directly if you are computing many hashes and want to minimize memory
/// allocations.
///
/// You can control the number of created isolates with [maxIsolates] and
/// [minBlocksPerSliceForEachIsolate]. The default values are usually good.
///
/// ## Examples
/// See documentation for the class [Argon2id].
class DartArgon2id extends Argon2id {
  @override
  final int parallelism;

  @override
  final int memory;

  @override
  final int iterations;

  @override
  final int hashLength;

  /// Maximum number of isolates to use.
  final int? maxIsolates;

  /// Minimum number of blocks per isolate.
  final int? minBlocksPerSliceForEachIsolate;

  /// How often (number of blocks) to give computing time to other concurrent
  /// tasks.
  final int? blocksPerProcessingChunk;

  const DartArgon2id({
    required this.parallelism,
    required this.memory,
    required this.iterations,
    required this.hashLength,
    this.maxIsolates,
    this.minBlocksPerSliceForEachIsolate,
    this.blocksPerProcessingChunk,
  })  : assert(parallelism >= 1),
        assert(memory >= 8 * parallelism),
        assert(iterations >= 1),
        assert(hashLength >= 4),
        super.constructor();

  @override
  int get hashCode => super.hashCode ^ blocksPerProcessingChunk.hashCode;

  @override
  bool operator ==(other) =>
      other is DartArgon2id &&
      super == other &&
      maxIsolates == other.maxIsolates &&
      minBlocksPerSliceForEachIsolate ==
          other.minBlocksPerSliceForEachIsolate &&
      blocksPerProcessingChunk == other.blocksPerProcessingChunk;

  @override
  Future<SecretKey> deriveKey({
    required SecretKey secretKey,
    required List<int> nonce,
    List<int> optionalSecret = const <int>[],
    List<int> associatedData = const <int>[],
  }) async {
    final state = newState();
    try {
      final bytes = await state.deriveKeyBytes(
        password: await secretKey.extractBytes(),
        nonce: nonce,
        optionalSecret: optionalSecret,
        associatedData: associatedData,
      );
      return SecretKey(bytes);
    } finally {
      state.tryReleaseMemory();
    }
  }

  /// Constructs an instance of [DartArgon2State].
  DartArgon2State newState() {
    return DartArgon2State(
      version: version,
      mode: DartArgon2Mode.argon2id,
      memory: memory,
      parallelism: parallelism,
      iterations: iterations,
      hashLength: hashLength,
      maxIsolates: maxIsolates,
      minBlocksPerSliceForEachIsolate: minBlocksPerSliceForEachIsolate,
      blocksPerProcessingChunk: blocksPerProcessingChunk,
    );
  }
}

/// Argon2 mode for [DartArgon2State].
enum DartArgon2Mode {
  argon2d,
  argon2i,
  argon2id;

  int get code => index;
}

/// State for three Argon2-based algorithms (Argon2d, Argon2i, [Argon2id]).
///
/// If you want to minimize memory allocations, you can re-use the same state
/// for different hash computations.
///
/// You can control the number of created isolates with [maxIsolates] and
/// [minBlocksPerSliceForEachIsolate]. The default values are usually good.
abstract class DartArgon2State {
  /// All-zeroes block.
  static final _zeroBlock = Uint32List(256);

  final int parallelism;
  final int memory;
  final int iterations;
  final int hashLength;
  final DartArgon2Mode mode;
  final int version;
  final int? maxIsolates;
  final int? minBlocksPerSliceForEachIsolate;
  final int? blocksPerProcessingChunk;
  final _addressBlock = Uint32List(256);
  final _addressBlockParametersBlock = Uint32List(256);
  final _tmpBlock = Uint32List(256);

  /// For preventing concurrent computations using the same state.
  Future? _futureOfLastScheduledComputation;

  /// Number of blocks, which may be different from [memory].
  late final int blockCount = () {
    // In the RFC 9106:
    //   m' = 4 * p * floor (m / 4p)
    return 4 * parallelism * (memory ~/ (4 * parallelism));
  }();

  List<_Block>? _blocks;

  bool _isBufferUsed = false;

  factory DartArgon2State({
    required DartArgon2Mode mode,
    required int parallelism,
    required int memory,
    required int iterations,
    required int hashLength,
    int? maxIsolates,
    int? minBlocksPerSliceForEachIsolate,
    int? blocksPerProcessingChunk,
    int version,
    ByteBuffer? buffer,
  }) = DartArgon2StateImpl;

  DartArgon2State.constructor({
    this.version = 19,
    required this.mode,
    required this.parallelism,
    required this.memory,
    required this.iterations,
    required this.hashLength,
    this.maxIsolates,
    this.minBlocksPerSliceForEachIsolate,
    this.blocksPerProcessingChunk,
  }) {
    checkSystemIsLittleEndian();
    if (parallelism < 1) {
      throw ArgumentError.value(parallelism, 'parallelism');
    }
    if (memory < 8 * parallelism) {
      throw ArgumentError.value(memory, 'memory');
    }
    if (hashLength < 4) {
      throw ArgumentError.value(hashLength, 'hashLength');
    }
    if (iterations < 1) {
      throw ArgumentError.value(iterations, 'iterations');
    }
  }

  int get blocksPerLane => blockCount ~/ parallelism;

  int get blocksPerSegment => blocksPerLane ~/ 4;

  bool get isBufferUsed => _isBufferUsed;

  /// Number of isolates used by the state.
  int get isolateCount => 0;

  /// Computes result of the given parameters.
  Future<List<int>> deriveKeyBytes({
    required List<int> password,
    List<int> nonce = const [],
    List<int> optionalSecret = const [],
    List<int> associatedData = const [],
  }) async {
    // Compute hash of the parameters.
    final h0 = preHashingDigest(
      password: password,
      nonce: nonce,
      optionalSecret: optionalSecret,
      associatedData: associatedData,
    );

    final result = await deriveKeyBytesFromPrehashingDigest(h0);
    h0.fillRange(0, h0.length, 0);
    return result;
  }

  @visibleForTesting
  Future<List<int>> deriveKeyBytesFromPrehashingDigest(Uint8List h0) async {
    final futureOfPreviousComputation = _futureOfLastScheduledComputation;
    final completer = Completer();
    final future = completer.future;
    _futureOfLastScheduledComputation = future;
    if (futureOfPreviousComputation != null) {
      await futureOfPreviousComputation;
    }

    getByteBuffer();
    _isBufferUsed = true;
    try {
      // Initialize blocks.
      initialize(h0: h0);

      // Compute lanes after N iterations.
      await iterate();

      // Constructs the output.
      final result = _getOutput();

      return result;
    } finally {
      _isBufferUsed = false;

      // If this is the last scheduled computation,
      // clear the variable.
      if (identical(_futureOfLastScheduledComputation, future)) {
        _futureOfLastScheduledComputation = null;
      }

      // If someone is waiting for the state,
      // signal that it's ready for use.
      completer.complete();
    }
  }

  /// RFC 9106 function GB(v0,..v3).
  ///
  /// In the RFC, arguments are 64-bit integers. In our implementation, they
  /// are Uint32List indices.
  @visibleForTesting
  void gb(Uint32List data, int a, int b, int c, int d) {
    // ---------------------------------
    // Browser-compatible implementation
    // ---------------------------------
    var v0Low = data[a];
    var v0High = data[a + 1];
    var v1Low = data[b];
    var v1High = data[b + 1];
    var v2Low = data[c];
    var v2High = data[c + 1];
    var v3Low = data[d];
    var v3High = data[d + 1];

    // a = (a + b + 2 * trunc(a) * trunc(b)) mod 2^(64)
    {
      var mLow =
          (0xFFFF & v0Low) * v1Low + (0xFFFF0000 & v0Low) * (0xFFFF & v1Low);
      var mHigh = mLow ~/ _bit32 + (v0Low >> 16) * (v1Low >> 16);
      mHigh = (_mask32 & (mHigh << 1)) + (0x1 & (mLow >> 31));
      mLow = _mask32 & (mLow << 1);
      v0Low = v0Low + v1Low + mLow;
      v0High = _mask32 & (v0High + v1High + v0Low ~/ _bit32 + mHigh);
      v0Low = _mask32 & v0Low;
    }

    // d = (d XOR a) rotr 32
    {
      final tmpLow = v3Low ^ v0Low;
      final tmpHigh = v3High ^ v0High;
      v3Low = tmpHigh;
      v3High = tmpLow;
    }

    // c = (c + d + 2 * trunc(c) * trunc(d)) mod 2^(64)
    {
      var mLow =
          (0xFFFF & v2Low) * v3Low + (0xFFFF0000 & v2Low) * (0xFFFF & v3Low);
      var mHigh = mLow ~/ _bit32 + (v2Low >> 16) * (v3Low >> 16);
      mHigh = (_mask32 & (mHigh << 1)) + (0x1 & (mLow >> 31));
      mLow = _mask32 & (mLow << 1);
      v2Low = v2Low + v3Low + mLow;
      v2High = _mask32 & (v2High + v3High + v2Low ~/ _bit32 + mHigh);
      v2Low = _mask32 & v2Low;
    }

    // b = (b XOR c) rotr 24
    {
      final tmpLow = v1Low ^ v2Low;
      final tmpHigh = v1High ^ v2High;
      v1Low = ((0xFFFFFF & tmpHigh) << 8) | (tmpLow >>> 24);
      v1High = ((0xFFFFFF & tmpLow) << 8) | (tmpHigh >>> 24);
    }

    // a = (a + b + 2 * trunc(a) * trunc(b)) mod 2^(64)
    {
      var mLow =
          (0xFFFF & v0Low) * v1Low + (0xFFFF0000 & v0Low) * (0xFFFF & v1Low);
      var mHigh = mLow ~/ _bit32 + (v0Low >> 16) * (v1Low >> 16);
      mHigh = (_mask32 & (mHigh << 1)) + (0x1 & (mLow >> 31));
      mLow = _mask32 & (mLow << 1);
      v0Low = v0Low + v1Low + mLow;
      v0High = _mask32 & (v0High + v1High + v0Low ~/ _bit32 + mHigh);
      v0Low = _mask32 & v0Low;
    }

    // d = (d XOR a) rotr 16
    {
      final tmpLow = v3Low ^ v0Low;
      final tmpHigh = v3High ^ v0High;
      v3Low = ((0xFFFF & tmpHigh) << 16) | (tmpLow >>> 16);
      v3High = ((0xFFFF & tmpLow) << 16) | (tmpHigh >>> 16);
    }

    // c = (c + d + 2 * trunc(c) * trunc(d)) mod 2^(64)
    {
      var mLow =
          (0xFFFF & v2Low) * v3Low + (0xFFFF0000 & v2Low) * (0xFFFF & v3Low);
      var mHigh = mLow ~/ _bit32 + (v2Low >> 16) * (v3Low >> 16);
      mHigh = (_mask32 & (mHigh << 1)) + (0x1 & (mLow >> 31));
      mLow = _mask32 & (mLow << 1);
      v2Low = v2Low + v3Low + mLow;
      v2High = _mask32 & (v2High + v3High + v2Low ~/ _bit32 + mHigh);
      v2Low = _mask32 & v2Low;
    }

    // b = (b XOR c) rotr 63
    {
      final tmpLow = v1Low ^ v2Low;
      final tmpHigh = v1High ^ v2High;
      v1Low = (_mask32 & (tmpLow << 1)) | (tmpHigh >>> 31);
      v1High = (tmpHigh << 1) | (tmpLow >>> 31);
    }

    data[a] = v0Low;
    data[a + 1] = v0High;
    data[b] = v1Low;
    data[b + 1] = v1High;
    data[c] = v2Low;
    data[c + 1] = v2High;
    data[d] = v3Low;
    data[d + 1] = v3High;
  }

  Uint32List getBlock({
    required int lane,
    required int slice,
    required int index,
  }) {
    final blocks = _blocks ??= _allocateBlocks();
    final blocksPerLane = blockCount ~/ parallelism;
    final blocksPerSegment = blocksPerLane ~/ 4;
    final blockIndex = lane * blocksPerLane + slice * blocksPerSegment + index;
    assert(
      blockIndex >= 0 && blockIndex < blocks.length,
      'blockIndex=$blockIndex, blockCount=$blockCount parallelism=$parallelism lane=$lane, slice=$slice, index=$index',
    );
    return blocks[blockIndex];
  }

  @protected
  ByteBuffer getByteBuffer();

  /// Initializes the first two blocks of every lane.
  @visibleForTesting
  void initialize({
    required Uint8List h0,
  }) {
    if (h0.length != 64) {
      throw ArgumentError();
    }

    // Our implementation uses the third block for temporarily storing input for
    // the hash function.
    final thirdBlock = getBlock(lane: 0, slice: 0, index: 3);
    final input = Uint8List.view(
      thirdBlock.buffer,
      thirdBlock.offsetInBytes,
      _blake2bSize + 8,
    );
    input.setAll(0, h0);

    final inputByteData = ByteData.view(
      input.buffer,
      input.offsetInBytes,
      input.lengthInBytes,
    );

    // For each lane
    for (var lane = 0; lane < parallelism; lane++) {
      // Set lane index
      inputByteData.setUint32(
        64 + 4,
        lane,
        Endian.little,
      );

      // Block 0 of the lane
      {
        // Set block index
        inputByteData.setUint32(
          64,
          0,
          Endian.little,
        );

        // BLAKE2B
        final block = getBlock(lane: lane, slice: 0, index: 0);
        variableLengthHash(
          output: block.buffer.asUint8List(
            block.offsetInBytes,
            block.lengthInBytes,
          ),
          input: input,
        );
      }

      // Block 1 of the lane
      {
        // Set: block index
        inputByteData.setUint32(
          64,
          1,
          Endian.little,
        );

        // BLAKE2B
        final block = getBlock(lane: lane, slice: 0, index: 1);
        variableLengthHash(
          output: block.buffer.asUint8List(
            block.offsetInBytes,
            block.lengthInBytes,
          ),
          input: input,
        );
      }
    }

    // Erase the temporary buffer
    input.fillRange(0, input.length, 0);
  }

  @visibleForTesting
  Future<void> iterate() async {
    //
    // For each iteration
    //
    for (var iteration = 0; iteration < iterations; iteration++) {
      //
      // For each of the four slices
      //
      for (var slice = 0; slice < 4; slice++) {
        for (var lane = 0; lane < parallelism; lane++) {
          await processSegment(
            iteration: iteration,
            slice: slice,
            lane: lane,
          );
        }
      }
    }
  }

  /// RFC 9106 function P(v0,...,v7).
  ///
  /// In the RFC, arguments are 128-bit values. In our implementation, they
  /// are Uint32List indices.
  @visibleForTesting
  void permutation(
    Uint32List data,
    int i0,
    int i1,
    int i2,
    int i3,
    int i4,
    int i5,
    int i6,
    int i7,
  ) {
    // The 8 x 128-bit arguments are broken down to two 4x4 matrix of 64-bit
    // integers.
    final x0 = i0 + 0;
    final x1 = i0 + 2;
    final x2 = i1 + 0;
    final x3 = i1 + 2;
    final x4 = i2 + 0;
    final x5 = i2 + 2;
    final x6 = i3 + 0;
    final x7 = i3 + 2;
    final x8 = i4 + 0;
    final x9 = i4 + 2;
    final x10 = i5 + 0;
    final x11 = i5 + 2;
    final x12 = i6 + 0;
    final x13 = i6 + 2;
    final x14 = i7 + 0;
    final x15 = i7 + 2;

    gb(data, x0, x4, x8, x12);
    gb(data, x1, x5, x9, x13);
    gb(data, x2, x6, x10, x14);
    gb(data, x3, x7, x11, x15);

    gb(data, x0, x5, x10, x15);
    gb(data, x1, x6, x11, x12);
    gb(data, x2, x7, x8, x13);
    gb(data, x3, x4, x9, x14);
  }

  /// Computes the pre-hashing digest.
  @visibleForTesting
  Uint8List preHashingDigest({
    required List<int> password,
    required List<int> nonce,
    required List<int> optionalSecret,
    required List<int> associatedData,
  }) {
    // Allocate bytes
    final capacity = 10 * 4 +
        password.length +
        nonce.length +
        optionalSecret.length +
        associatedData.length;
    final tmp = ByteData(capacity);

    // Set 6 fixed parameters
    var i = 0;
    tmp.setUint32(i, parallelism, Endian.little);
    i += 4;
    tmp.setUint32(i, hashLength, Endian.little);
    i += 4;
    tmp.setUint32(i, memory, Endian.little);
    i += 4;
    tmp.setUint32(i, iterations, Endian.little);
    i += 4;
    tmp.setUint32(i, version, Endian.little);
    i += 4;
    tmp.setUint32(i, mode.code, Endian.little);
    i += 4;

    // Set 4 variable-length parameters
    i = _setSequence(tmp, i, password);
    i = _setSequence(tmp, i, nonce);
    i = _setSequence(tmp, i, optionalSecret);
    i = _setSequence(tmp, i, associatedData);

    // BLAKE2
    final tmpBytes = Uint8List.view(
      tmp.buffer,
      tmp.offsetInBytes,
      tmp.lengthInBytes,
    );
    final result = const DartBlake2b().hashSync(tmpBytes).bytes as Uint8List;
    tmpBytes.fillRange(0, tmpBytes.length, 0);
    return result;
  }

  /// Processes a block.
  ///
  /// Parameters [output], [input0], [input1], and [tmp] are 1024 byte blocks.
  @visibleForTesting
  void processBlock({
    required Uint32List output,
    required Uint32List input0,
    required Uint32List input1,
    required bool isXorred,
  }) {
    final tmp = _tmpBlock;

    // In the specification:
    //   R = X ⊕ Y
    for (var i = 0; i < 256; i++) {
      tmp[i] = input0[i] ^ input1[i];
    }

    // Apply to P to each row
    //
    // Note that the input t the function P is:
    //   8 * 16 bytes = 32 * uint32
    for (var i = 0; i < 8; i++) {
      final row = i * 32;
      permutation(
        tmp,
        row,
        row + 4,
        row + 8,
        row + 12,
        row + 16,
        row + 20,
        row + 24,
        row + 28,
      );
    }

    // Apply to P to each column
    for (var i = 0; i < 8; i++) {
      final column = i * 4;
      permutation(
        tmp,
        0 + column,
        32 + column,
        64 + column,
        96 + column,
        128 + column,
        160 + column,
        192 + column,
        224 + column,
      );
    }

    // In the specification iteration:
    //   output = Z ⊕ R = Z ⊕ X ⊕ Y
    //
    // In the first iteration, we do not need to XOR without `output`.
    if (isXorred) {
      for (var i = 0; i < 256; i++) {
        output[i] ^= tmp[i] ^ input0[i] ^ input1[i];
      }
    } else {
      for (var i = 0; i < 256; i++) {
        output[i] = tmp[i] ^ input0[i] ^ input1[i];
      }
    }
  }

  @visibleForTesting
  Future<void> processSegment({
    required int iteration,
    required int slice,
    required int lane,
  }) async {
    final blocksPerLane = blockCount ~/ parallelism;
    final blocksPerSegment = blocksPerLane ~/ 4;
    var firstIndex = 0;
    if (iteration == 0 && slice == 0) {
      firstIndex = 2;
    }

    //
    // For each block in the segment
    //
    for (var index = firstIndex; index < blocksPerSegment; index++) {
      // Give time to other tasks after 500 blocks
      final blocksPerProcessingChunk = this.blocksPerProcessingChunk ?? 500;
      if (blocksPerProcessingChunk > 0 &&
          index % blocksPerProcessingChunk == 0 &&
          index > 0) {
        await Future.delayed(const Duration(microseconds: 1));
      }

      // Get previous block
      final previousBlock = getBlock(
        lane: lane,
        slice: index == 0 ? (slice - 1) % 4 : slice,
        index: (index - 1) % blocksPerSegment,
      );

      // Get reference block
      final referenceBlock = _getReferenceBlock(
        iteration: iteration,
        slice: slice,
        lane: lane,
        index: index,
        previousBlock: previousBlock,
      );

      // The new block will be computed from the previous block and
      // a pseudo-randomly chosen block [l,z].
      final outputBlock = getBlock(
        lane: lane,
        slice: slice,
        index: index,
      );

      processBlock(
        output: outputBlock,
        input0: previousBlock,
        input1: referenceBlock,
        isXorred: iteration > 0,
      );
    }
  }

  /// Finds a block using rules describes in the specification.
  @visibleForTesting
  (int, int) referredBlockIndex({
    required int iteration,
    required int slice,
    required int lane,
    required int index,
    required int j1,
    required int j2,
  }) {
    final blocksPerLane = blockCount ~/ parallelism;
    final blocksPerSegment = blocksPerLane ~/ 4;

    // In the RFC 9106:
    //   l = J_2 mod p
    //
    // During the first segment of the first iteration,
    // the current lane is used.
    var referenceLane = j2 % parallelism;
    if (iteration == 0 && slice == 0) {
      referenceLane = lane;
    }

    // Index of the first possible block.
    var candidatesStart = 0;

    // Number of possible blocks.
    var candidatesLength = 0;

    if (iteration == 0) {
      if (slice == 0 || referenceLane == lane) {
        candidatesLength = slice * blocksPerSegment + index - 1;
      } else {
        candidatesLength = slice * blocksPerSegment;
        if (index == 0) {
          candidatesLength--;
        }
      }
    } else {
      // This is not the first iteration.
      candidatesStart = ((slice + 1) % 4) * blocksPerSegment;
      candidatesLength = 3 * blocksPerSegment;

      // The previous blocks of the same segment are candidates if:
      //   * This is the first slice of the first iteration
      //   * OR the current lane is the reference lane
      if (referenceLane == lane) {
        candidatesLength += index - 1;
      } else if (index == 0) {
        candidatesLength--;
      }
    }
    final zz = referredBlockIndexZZ(j1, candidatesLength);
    final z = (candidatesStart + candidatesLength - 1 - zz) % blocksPerLane;
    return (referenceLane, z);
  }

  @protected
  int referredBlockIndexZZ(
    int j1,
    int candidatesLength,
  ) {
    // In the RFC 9106:
    //   x = J_1^2 / 2^(32)
    //   y = (|W| * x) / 2^(32)
    //   zz = |W| - 1 - y
    final xCarry =
        (((0xFFFF & j1) * j1) + ((0xFFFF0000 & j1) * (0xFFFF & j1))) ~/ _bit32;
    final x = _mask32 & ((j1 >> 16) * (j1 >> 16) + xCarry);
    final yCarry = (((0xFFFF & candidatesLength) * x) +
            ((0xFFFF0000 & candidatesLength) * (0xFFFF & x))) ~/
        _bit32;
    final y = _mask32 & ((candidatesLength >> 16) * (x >> 16) + yCarry);
    return y % candidatesLength;
  }

  /// Releases memory.
  @mustCallSuper
  void tryReleaseMemory() {
    if (isBufferUsed) {
      return;
    }
    _blocks = null;
  }

  /// RFC 9106 function H'^T(A).
  @visibleForTesting
  void variableLengthHash({
    required Uint8List output,
    required Uint8List input,
  }) {
    final outputLength = output.length;
    final blake2b = const DartBlake2b().replace(
      hashLength: min<int>(outputLength, 64),
    );
    var sink = blake2b.newHashSink();
    sink.add([
      0xFF & outputLength,
      0xFF & (outputLength >>> 8),
      0xFF & (outputLength >>> 16),
      0xFF & (outputLength >>> 24),
    ]);
    sink.add(input);
    sink.close();
    if (outputLength <= 64) {
      output.setAll(0, sink.hashBytes);
      return;
    }

    input = Uint8List.fromList(sink.hashBytes);
    output.setAll(0, sink.hashBytes.take(32));
    var remainingLength = outputLength - 32;
    var outputIndex = 32;
    input = Uint8List.fromList(sink.hashBytes);
    sink.reset();

    while (remainingLength > 64) {
      sink.add(input);
      sink.close();
      output.setAll(outputIndex, sink.hashBytes);
      outputIndex += 32;
      remainingLength -= 32;
      input.setAll(0, sink.hashBytes);
      sink.reset();
    }

    if (output.length % 64 != 0) {
      sink = blake2b.replace(hashLength: remainingLength).newHashSink();
    }
    sink.add(input);
    sink.close();
    output.setAll(outputIndex, sink.hashBytes);
  }

  /// Allocates memory for lanes.
  List<Uint32List> _allocateBlocks() {
    final buffer = getByteBuffer();
    return List<_Block>.generate(blockCount, (index) {
      return Uint32List.view(
        buffer,
        1024 * index,
        256,
      );
    });
  }

  /// Computes Blake2b hash of XORred last blocks.
  List<int> _getOutput() {
    // The last block of the last lane will be used for storing XORred block.
    final lastBlock = getBlock(
      lane: parallelism - 1,
      slice: 3,
      index: blocksPerSegment - 1,
    );

    // For each last block (except the last lane)
    for (var lane = 0; lane < parallelism - 1; lane++) {
      final lastBlockOfLane = getBlock(
        lane: lane,
        slice: 3,
        index: blocksPerSegment - 1,
      );

      // lastBlock ^= block
      for (var i = 0; i < 256; i++) {
        lastBlock[i] ^= lastBlockOfLane[i];
      }
    }

    final output = Uint8List(hashLength);
    variableLengthHash(
      output: output,
      input: lastBlock.buffer.asUint8List(
        lastBlock.offsetInBytes,
        lastBlock.lengthInBytes,
      ),
    );
    return output;
  }

  _Block _getReferenceBlock({
    required int iteration,
    required int slice,
    required int lane,
    required int index,
    required _Block previousBlock,
  }) {
    // Argon2d and Argon2i have different algorithms for computing j1
    // and j2.
    //
    // Argon2id uses uses Argon2d for the first two slices and
    // Argon2i for the other two slices.
    var jAlgorithm = mode;
    if (jAlgorithm == DartArgon2Mode.argon2id) {
      if (slice < 2 && iteration == 0) {
        jAlgorithm = DartArgon2Mode.argon2i;
      } else {
        jAlgorithm = DartArgon2Mode.argon2d;
      }
    }

    var j1 = 0;
    var j2 = 0;
    if (jAlgorithm == DartArgon2Mode.argon2i) {
      // j1, j2 are calculated with Argon2d algorithm
      //
      // Initialize the address block if this is the first computed block of
      // the segment.
      final addressBlock = _addressBlock;
      var addressIndex = index % 128;

      if (addressIndex == 0 || (index == 2 && slice == 0 && iteration == 0)) {
        // Initialize the input block
        final parametersBlock = _addressBlockParametersBlock;
        parametersBlock[0] = iteration;
        parametersBlock[2] = lane;
        parametersBlock[4] = slice;
        parametersBlock[6] = blockCount;
        parametersBlock[8] = iterations;
        parametersBlock[10] = mode.code;
        parametersBlock[12] = 1 + index ~/ 128;

        processBlock(
          output: addressBlock,
          input0: parametersBlock,
          input1: _zeroBlock,
          isXorred: false,
        );
        processBlock(
          output: addressBlock,
          input0: addressBlock,
          input1: _zeroBlock,
          isXorred: false,
        );
      }

      // Get j1, j2
      j1 = addressBlock[2 * addressIndex];
      j2 = addressBlock[2 * addressIndex + 1];
    } else {
      //
      // j1, j2 are calculated with this simple Argon2i algorithm
      //
      j1 = previousBlock[0];
      j2 = previousBlock[1];
    }
    final (referenceLane, z) = referredBlockIndex(
      iteration: iteration,
      slice: slice,
      lane: lane,
      index: index,
      j1: j1,
      j2: j2,
    );
    return getBlock(
      lane: referenceLane,
      slice: z ~/ blocksPerSegment,
      index: z % blocksPerSegment,
    );
  }

  /// Used by [preHashingDigest].
  static int _setSequence(ByteData buffer, int i, List<int> data) {
    buffer.setUint32(i, data.length, Endian.little);
    i += 4;
    for (var j = 0; j < data.length; j++) {
      buffer.setUint8(i + j, data[j]);
    }
    i += data.length;
    return i;
  }
}
