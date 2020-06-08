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

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/src/utils.dart';

import '../utils/random_bytes.dart';

/// A secret key.
///
/// You can generate a random secret key with [SecretKey.randomBytes].
///
/// In asymmetric cryptography, you should use [PrivateKey] instead of this
/// class.
///
/// ## Examples
/// See [Cipher] documentation.
abstract class SecretKey {
  Map<Object, Object> _cachedValues;

  /// Constructs an instance with the bytes.
  factory SecretKey(List<int> bytes) = _SecretKey;

  /// A constructor for subclasses.
  SecretKey.constructor();

  /// Generates _N_ random bytes with a cryptographically secure random number
  /// generator.
  ///
  /// A description of the random number generator:
  ///   * In browsers, `window.crypto.getRandomValues() is used directly.
  ///   * In Dart, _dart:math_ [Random.secure()] is used.
  ///
  /// You can give a custom random number generator. This can be useful for
  /// deterministic tests.
  ///
  /// ```
  /// // Generate 32 random bytes
  /// final key = Nonce.randomBytes(32);
  /// ```
  factory SecretKey.randomBytes(int length, {Random random}) {
    final data = Uint8List(length);
    fillBytesWithSecureRandomNumbers(data, random: random);
    return SecretKey(data);
  }

  /// Used internally by _package:cryptography_ for caching cryptographic
  /// objects such as Web Cryptography _CryptoKey_ references and AES key after
  /// expansion.
  Map<Object, Object> get cachedValues => _cachedValues ??= <Object, Object>{};

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

  _SecretKey(this._bytes)
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
