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

import 'dart:math' show Random;
import 'dart:typed_data';

import 'package:cryptography/utils.dart';

/// A secret sequence of bytes.
///
/// You can generate a random secret key with [SecretKey.randomBytes].
///
/// The equality operator uses [constantTimeBytesEquality].
///
/// For examples of usage, see [Cipher].
abstract class SecretKey {
  static final _random = Random.secure();

  /// Constructs a secret key on the heap.
  const factory SecretKey(List<int> bytes) = _SecretKey;

  /// Constructor for subclasses.
  const SecretKey.constructor();

  /// Generates _N_ random bytes with a cryptographically strong random number
  /// generator.
  ///
  /// You can optionally give a custom random number generator.
  ///
  /// ```
  /// // Generate 32 random bytes
  /// final key = Nonce.randomBytes(32);
  /// ```
  factory SecretKey.randomBytes(int length, {Random random}) {
    random ??= _random;
    final data = Uint8List(length);
    for (var i = 0; i < data.length; i++) {
      data[i] = random.nextInt(256);
    }
    return SecretKey(data);
  }

  /// Attempts to extract the bytes asynchronously.
  /// Throws [UnsupportedError] if extraction is forbidden / unavailable.
  ///
  /// The returned byte list should be treated as immutable.
  Future<List<int>> extract() {
    return Future<List<int>>.value(extractSync());
  }

  /// Attempts to extract the bytes synchronously.
  /// Throws [UnsupportedError] if extraction is forbidden / unavailable.
  ///
  /// The returned byte list should be treated as immutable.
  List<int> extractSync();
}

class _SecretKey extends SecretKey {
  final List<int> _bytes;

  const _SecretKey(this._bytes)
      : assert(_bytes != null),
        super.constructor();

  @override
  int get hashCode {
    var h = 0;
    final bytes = _bytes;
    for (var i = 0; i < bytes.length; i++) {
      final b = bytes[i];

      // Exposes at most 31 bits
      h = 0x7FFFFFFF & ((31 * h) ^ b);
    }

    // For short values, expose max 15 bits.
    if (bytes.length < 8) {
      h = 0x7FFF & h;
    }

    return h;
  }

  @override
  bool operator ==(other) {
    return other is _SecretKey &&
        constantTimeBytesEquality.equals(_bytes, other._bytes);
  }

  @override
  List<int> extractSync() => _bytes;

  @override
  String toString() => 'SecretKey(...)';
}
