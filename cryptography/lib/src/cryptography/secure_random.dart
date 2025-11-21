// Copyright 2023 Gohilla.
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

import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/dart.dart';
import 'package:meta/meta.dart';

const _bit20 = 0x100000;
const _bit32 = 0x100000000;
const _bit52 = 0x10000000000000;

/// An abstract base class for secure [Random] implementations.
abstract class SecureRandom implements Random {
  /// An instance of [ChaChaRandom], which can be over 100 times faster than
  /// [Random.secure].
  ///
  /// The algorithm is based on ChaCha20 stream cipher and is cryptographically
  /// secure. Reseeding is done from [Random.secure] at least once every 8192
  /// blocks or 10 milliseconds.
  static final SecureRandom fast = ChaChaRandom();

  /// [Random] instance that is used as default by "package:cryptography".
  ///
  /// Currently this is always [SecureRandom.system].
  static final Random defaultRandom = system;

  @Deprecated('Use SecureRandom.defaultRandom instead')
  static Random get safe => defaultRandom;

  /// System-provided secure random number generator.
  ///
  /// This is equivalent to [Random.secure].
  static final Random system = Random.secure();

  /// A previously generated random bits (maximum 32).
  ///
  /// The remaining bits are stored in the lowest bits.
  ///
  /// The field [_wordBitsRemaining] tells how many bits are left.
  int _word = 0;

  /// How many random bits [_word] has left.
  int _wordBitsRemaining = 0;

  /// Constructor for subclasses.
  SecureRandom.constructor();

  /// Returns a deterministic [Random] for testing purposes.
  ///
  /// The sequence of outputs is a pure function of the [seed] you give to the
  /// constructor. This is only for meant for testing.
  ///
  /// ## Example
  /// ```dart
  /// import 'package:cryptography/cryptography.dart';
  ///
  /// void main() {
  ///   final random = SecureRandom.forTesting(seed: 0);
  ///   final a = random.nextInt(1000);
  ///   final b = random.nextInt(1000);
  ///   final c = random.nextInt(1000);
  ///   print('$a, $b, $c');
  ///   // Always prints:
  ///   //
  ///   // 412, 913, 198
  ///   //
  ///   // Because it's a fake random number generator for testing only!
  /// }
  /// ```
  factory SecureRandom.forTesting({
    int seed = 0,
  }) {
    return ChaChaRandom.forTesting(seed: seed);
  }

  /// Tells whether the algorithm is cryptographically secure and
  /// the initial entropy is from [Random.secure].
  bool get isSecure;

  @nonVirtual
  @override
  bool nextBool() {
    // We will use the lowest bit of `_word`.
    var word = _word;
    var wordBitsRemaining = _wordBitsRemaining;
    if (wordBitsRemaining >= 1) {
      // Drop the lowest bit.
      _word = word >> 1;
      _wordBitsRemaining = wordBitsRemaining - 1;
    } else {
      // Get a new word.
      word = nextUint32();
      _word = word >> 1;
      _wordBitsRemaining = 31;
    }

    // Return the lowest bit.
    return 0x1 & word != 0;
  }

  @nonVirtual
  @override
  double nextDouble() {
    // We need to generate a double in [0.0, 1.0).
    while (true) {
      // Generate random 20 bits.
      final a = (_bit20 - 1) & nextUint32();

      // Generate random 32 bits.
      final b = nextUint32();

      // Combine to a 52-bit integer and convert to double in [0.0, 1.0).
      final x = (a * _bit32 + b) / _bit52;

      // Return the value if it's in [0.0, 1.0).
      if (x >= 0.0 && x < 1.0) {
        return x;
      }

      // This should never happen,
      // but we will just generate another pair if it does.
      assert(false);
    }
  }

  @nonVirtual
  @override
  int nextInt(int max) {
    if (max < 0 || max > _bit32) {
      throw ArgumentError.value(max, 'max');
    }
    var attempts = 0;
    while (true) {
      final x = nextUint32();

      // To avoid modulo bias, we only accept values
      // that are within a multiple of [max].
      final nonAcceptedRange = _bit32 % max;
      if (x < _bit32 - nonAcceptedRange) {
        // Accept the value.
        return x % max;
      }
      if (attempts == 128) {
        // Give up and accept the value anyway.
        // This should never happen.
        assert(false);
        return x % max;
      }
      attempts++;
    }
  }

  /// Returns a random unsigned 32-bit integer.
  int nextUint32();

  /// Returns a random cross-platform unsigned 52-bit integer.
  ///
  /// Note that 52-bit integers, unlike 64-bit integers, can always be
  /// accurately represented in JavaScript.
  @nonVirtual
  int nextUint52([int? max]) {
    if (max != null && (max < 0 || max > _bit52)) {
      throw ArgumentError.value(max, 'max');
    }
    var attempts = 0;
    while (true) {
      // Generate a 52-bit integer from two 32-bit integers.
      final high = nextUint32();
      final low = nextUint32();
      final x = ((_bit32 * (0xFFFFF & high)) + low);
      if (max == null) {
        return x;
      }
      // To avoid modulo bias, we only accept values
      // that are within a multiple of [max].
      final nonAcceptedRange = _bit52 % max;
      if (x < _bit52 - nonAcceptedRange) {
        return x % max;
      }
      if (attempts == 128) {
        // Give up and accept the value anyway.
        // This should never happen.
        assert(false);
        return x % max;
      }
      attempts++;
    }
  }

  @mustCallSuper
  void reset() {
    _word = 0;
    _wordBitsRemaining = 0;
  }
}

/// ChaCha20-based [SecureRandom] implementation.
///
/// The throughput is up to about 0.25 GB of random data per second. This is
/// over 100 times faster than [Random.secure] on many platforms.
///
/// ## Current algorithm
/// The default behavior is:
///   * 12 rounds of ChaCha. No key extraction attack has been proposed against
///     ChaCha with more than 6 rounds so the choice has a good margin of
///     safety.
///   * 256-bit secret key is mixed (XOR) with numbers from [Random.secure] at
///     least once every 8192 blocks. This is also done if more than 10
///     milliseconds has passed since the last reseed event.
///   * After a block has been computed, the block counter is incremented.
///   * After a block has been computed, the last 128 bits of the secret key
///     is immediately mixed (XOR) with the first 128 bits of the state.
///     The first 128-bits of the state are then zeroed and skipped.
///     This provides backtracking resistance.
///   * State bits are erased after they have been read so a memory dump won't
///     reveal them.
///
/// ## Example
/// ```dart
/// import 'package:cryptography/random.dart';
///
/// void main() {
///   final random = SecureRandom.fast;
///   final x = random.nextInt(100);
///   print('x = $x');
/// }
/// ```
class ChaChaRandom extends SecureRandom {
  static const int _bit32 = 0x100000000;

  /// Default value for [rounds].
  static const int defaultRounds = 12;

  /// Default value for [maxBlocksBeforeReseed].
  static const int defaultMaxBlocksBeforeReseed = 8192;

  /// Default value for [maxDurationBeforeReseed].
  static const Duration defaultMaxDurationBeforeReseed =
      Duration(milliseconds: 10);

  /// Generated block of random numbers.
  final _state = Uint32List(16);

  /// Index of the next 32-bit random number in [_state].
  int _stateIndex = 0;

  /// Number of blocks generated from the current seed.
  int _blockCount = 0;

  /// ChaCha initial state.
  final _initialState = Uint32List(16);

  /// Stopwatch used for measuring time since the last reseed.
  final Stopwatch _stopwatch = Stopwatch()..start();

  /// Number of times the random number generator has been reseeded.
  int _reseedCount = 0;

  final Random _random = Random.secure();

  /// Number of ChaCha rounds.
  final int rounds;

  final int? _seedForDeterministicSequence;

  /// Maximum number of 64 byte blocks since the last reseed before the random
  /// number generator must be reseeded.
  final int maxBlocksBeforeReseed;

  /// Maximum elapsed time since the last reseed before the random number
  /// generator must be reseeded.
  final Duration? maxDurationBeforeReseed;

  ChaChaRandom({
    this.rounds = defaultRounds,
    this.maxBlocksBeforeReseed = defaultMaxBlocksBeforeReseed,
    this.maxDurationBeforeReseed = defaultMaxDurationBeforeReseed,
  })  : _seedForDeterministicSequence = null,
        super.constructor() {
    if (maxBlocksBeforeReseed < 0 || maxBlocksBeforeReseed > _bit32) {
      throw ArgumentError.value(
        maxBlocksBeforeReseed,
        ' maxBlocksBeforeReseed',
      );
    }
  }

  ChaChaRandom.forTesting({
    int seed = 0,
  })  : _seedForDeterministicSequence = seed,
        rounds = defaultRounds,
        maxBlocksBeforeReseed = defaultMaxBlocksBeforeReseed,
        maxDurationBeforeReseed = defaultMaxDurationBeforeReseed,
        super.constructor() {
    // Put the seed to the lowest bits of the secret key.
    _initialState[4] = seed;
    _initialState[5] = seed ~/ _bit32;
  }

  @override
  bool get isSecure => _seedForDeterministicSequence == null;

  @visibleForTesting
  int get reseedCount => _reseedCount;

  /// Whether it's time to mix in new values from [Random.secure].
  ///
  /// We reseed when:
  ///  * No blocks have been generated yet.
  ///  * The number of generated blocks since the last reseed is greater than or
  ///    equal to [maxBlocksBeforeReseed].
  ///  * The elapsed time since the last reseed is greater than or equal to
  ///    [maxDurationBeforeReseed].
  bool get _isTimeForMixinSystemRandom {
    final blockCount = _blockCount;
    final maxDurationBeforeReseed = this.maxDurationBeforeReseed;
    final isFirstBlock = blockCount == 0;
    return isFirstBlock ||
        blockCount >= maxBlocksBeforeReseed ||
        (maxDurationBeforeReseed != null &&
            _stopwatch.elapsedMicroseconds >
                maxDurationBeforeReseed.inMicroseconds);
  }

  @override
  int nextUint32() {
    final state = _state;
    var stateIndex = _stateIndex;
    if (stateIndex == 0) {
      _nextBlock();

      // Skip the first 4 integers of the state, which was consumed for
      // backtracking protection.
      stateIndex = 4;
    }

    // Get the next random number
    final result = state[stateIndex];

    // Increment state index.
    _stateIndex = (stateIndex + 1) % 16;

    // Erase the number.
    state[stateIndex] = 0;

    return result;
  }

  @override
  void reset() {
    super.reset();
    _blockCount = 0;
    _stateIndex = 0;
    _nextBlock();
  }

  @override
  String toString() {
    final seed = _seedForDeterministicSequence;
    if (seed != null) {
      return 'SecureRandom.forTesting(seed: $seed)';
    }
    return 'SecureRandom()';
  }

  /// Mixes new entropy from [Random.secure] into the state.
  void _mixSystemRandom() {
    // Reset stopwatch and block count.
    _stopwatch.reset();
    _blockCount = 0;

    // For debugging purposes, count reseeds.
    _reseedCount++;

    // Constants are stored at indices 0-3.
    final initialState = _initialState;
    initialState[0] = 0x61707865;
    initialState[1] = 0x3320646e;
    initialState[2] = 0x79622d32;
    initialState[3] = 0x6b206574;

    final random = _random;

    // Whether we are producing a deterministic sequence.
    final isDeterministicSequence = _seedForDeterministicSequence != null;

    // Mix the secret key with Random.secure bits.
    for (var i = 4; i < 12; i++) {
      final x = random.nextInt(_bit32);
      if (!isDeterministicSequence) {
        initialState[i] ^= x;
      }
    }

    // Block counter is stored at index 12.

    // Mix the nonce with Random.secure bits.
    for (var i = 13; i < 16; i++) {
      final x = random.nextInt(_bit32);
      if (!isDeterministicSequence) {
        initialState[i] ^= x;
      }
    }
  }

  void _nextBlock() {
    // Reseed?
    final initialState = _initialState;
    if (_isTimeForMixinSystemRandom) {
      _mixSystemRandom();
    }

    // Set block counter
    final blockCount = _blockCount;
    initialState[12] = blockCount;
    _blockCount = blockCount + 1;

    // ChaCha rounds
    final state = _state;
    DartChacha20.chachaRounds(
      state,
      0,
      initialState,
      rounds: rounds,
    );

    // Mix the last 128 bits of the secret key with the first 128 bits of the
    // state.
    initialState[8] ^= state[0];
    initialState[9] ^= state[1];
    initialState[10] ^= state[2];
    initialState[11] ^= state[3];

    // Empty state.
    state[0] = 0;
    state[1] = 0;
    state[2] = 0;
    state[3] = 0;
  }
}
