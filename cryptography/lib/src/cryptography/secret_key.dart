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

import 'dart:typed_data' show Uint8List;

import 'package:cryptography/cryptography.dart';
import 'package:meta/meta.dart';

import '../utils.dart';

/// An opaque reference to a secret sequence of bytes.
///
/// Secret keys are required by [Cipher], [MacAlgorithm], and
/// [KdfAlgorithm].
/// Typically the bytes are stored in the heap, in which case
/// [SecretKeyData] is used.
///
/// You can get bytes with [extractBytes()].
///
/// Note that public-key cryptographic algorithms use [SimpleKeyPair] /
/// [SimplePublicKey] instead of this class.
abstract class SecretKey {
  /// Constructs a secret key with the given bytes.
  // ignore: deprecated_member_use_from_same_package
  factory SecretKey(List<int> bytes) = SecretKeyData;

  SecretKey.constructor();

  factory SecretKey.lazy(Future<SecretKeyData> Function() f) = _LazySecretKey;

  /// Returns [SecretKeyData].
  ///
  /// Throws [UnsupportedError] if extraction is not possible.
  Future<SecretKeyData> extract();

  /// Returns bytes of the secret key.
  ///
  /// Throws [UnsupportedError] if extraction is not possible.
  Future<List<int>> extractBytes() => extract().then((value) => value.bytes);
}

/// A [SecretKey] that is stored in memory.
@sealed
class SecretKeyData extends SecretKey {
  final List<int> bytes;

  SecretKeyData(this.bytes) : super.constructor();

  /// Generates _N_ random bytes.
  ///
  /// A description of the random number generator:
  ///   * In browsers, `window.crypto.getRandomValues() is used directly.
  ///   * In Dart, _dart:math_ [Random.secure()] is used.
  ///
  /// You can give a custom random number generator. This can be useful for
  /// deterministic tests.
  ///
  /// ## Example
  /// ```
  /// // Generate 32 random bytes
  /// final key = SecretKey.randomBytes(32);
  /// ```
  factory SecretKeyData.random({
    required int length,
  }) {
    final bytes = Uint8List(length);
    fillBytesWithSecureRandom(bytes);
    return SecretKeyData(List<int>.unmodifiable(bytes));
  }

  @override
  int get hashCode => constantTimeBytesEquality.hash(bytes);

  @override
  bool operator ==(other) =>
      other is SecretKeyData &&
      constantTimeBytesEquality.equals(bytes, other.bytes);

  @override
  Future<SecretKeyData> extract() async {
    return Future<SecretKeyData>.value(this);
  }

  @override
  String toString() {
    return 'SecretKeyData(...)';
  }
}

class _LazySecretKey extends SecretKey {
  Future<SecretKeyData>? _future;
  Future<SecretKeyData> Function()? _function;

  _LazySecretKey(Future<SecretKeyData> Function() this._function)
      : super.constructor();

  @override
  Future<SecretKeyData> extract() {
    final oldFuture = _future;
    if (oldFuture != null) {
      return oldFuture;
    }
    final function = _function!;
    final future = function();
    _function = null;
    _future = future;
    return future;
  }
}
