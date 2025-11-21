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

import 'dart:math';
import 'dart:typed_data' show Uint8List;

import 'package:meta/meta.dart';

import '../../cryptography.dart';
import '../utils.dart';

/// An opaque reference to a secret sequence of bytes used for encryption and
/// message authentication.
///
/// The bytes of the key may not be in the memory.
/// You can try to extract the bytes with [extractBytes], which may throw an
/// error if the bytes are not extractable.
///
/// If the secret key is in memory, it's an instance of [SecretKeyData].
/// If you no longer need an in-memory secret key, you can optionally call
/// [SecretKeyData.destroy]. It overwrites the bytes and prevents the key from
/// being used in the future.
abstract class SecretKey {
  bool _isDestroyed = false;

  /// Constructs an instance of [SecretKeyData].
  factory SecretKey(List<int> bytes, {String? debugLabel}) = SecretKeyData;

  /// Constructor for subclasses.
  SecretKey.constructor();

  @Deprecated('This will be removed')
  factory SecretKey.lazy(Future<SecretKeyData> Function() f) = _LazySecretKey;

  /// Whether decryption is allowed with this key.
  bool get allowDecrypt => !isDestroyed;

  /// Whether encryption is allowed with this key.
  bool get allowEncrypt => !isDestroyed;

  /// Whether [destroy] has been called.
  bool get isDestroyed => _isDestroyed;

  /// Whether [extract] will succeed.
  bool get isExtractable => !isDestroyed;

  /// Destroys the secret key.
  void destroy() {
    _isDestroyed = true;
  }

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
///
/// The bytes can be accessed with [bytes]. The bytes can be destroyed with
/// [destroy]. After calling [destroy], the bytes are no longer accessible
/// and the getter [bytes] will throw [StateError].
@sealed
class SecretKeyData extends SecretKey {
  final SensitiveBytes _bytes;

  /// Debug label for the key.
  ///
  /// This is used in error messages and [toString]. It does not affect the
  /// equality of the key or other behavior.
  final String? debugLabel;

  /// Constructs a secret key with the given bytes.
  ///
  /// Optionally, you can provide a [debugLabel] that is used in error messages
  /// and [toString].
  ///
  /// If [overwriteWhenDestroyed] is true, the bytes will be overwritten with
  /// zeros when [destroy] is called.
  SecretKeyData(
    List<int> bytes, {
    bool overwriteWhenDestroyed = false,
    String? debugLabel,
  }) : this._(
          bytes,
          overwriteWhenDestroyed: overwriteWhenDestroyed,
          debugLabel: debugLabel,
        );

  /// Generates _N_ random bytes.
  ///
  /// A description of the random number generator:
  ///   * In browsers, `window.crypto.getRandomValues() is used directly.
  ///   * In other platforms, _dart:math_ [Random.secure()] is used.
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
    Uint8List? bytes,
    Random? random,
    String? debugLabel,
  }) {
    return SecretKeyData.randomWithBuffer(
      Uint8List(length),
      random: random,
      debugLabel: debugLabel,
    );
  }

  factory SecretKeyData.randomWithBuffer(
    Uint8List bytes, {
    Random? random,
    bool overwriteWhenDestroyed = true,
    String? debugLabel,
  }) {
    fillBytesWithSecureRandom(bytes, random: random);
    return SecretKeyData._(
      bytes,
      overwriteWhenDestroyed: overwriteWhenDestroyed,
      debugLabel: debugLabel,
    );
  }

  SecretKeyData._(
    List<int> bytes, {
    bool overwriteWhenDestroyed = false,
    this.debugLabel,
  })  : _bytes = SensitiveBytes(
          bytes,
          overwriteWhenDestroyed: overwriteWhenDestroyed,
        ),
        super.constructor();

  /// In-memory bytes of the secret key.
  ///
  /// If the key has been destroyed with [destroy], this throws [StateError].
  List<int> get bytes {
    final bytes = _bytes;
    if (bytes.hasBeenDestroyed) {
      throw StateError('Secret key has been destroyed: $this');
    }
    return bytes;
  }

  /// Whether the secret key has been destroyed with [destroy].
  bool get hasBeenDestroyed => _bytes.hasBeenDestroyed;

  @override
  int get hashCode =>
      (SecretKeyData).hashCode ^
      (hasBeenDestroyed ? 0 : constantTimeBytesEquality.hash(bytes));

  @override
  bool operator ==(other) {
    if (hasBeenDestroyed) {
      return false;
    }
    return other is SecretKeyData &&
        constantTimeBytesEquality.equals(bytes, other.bytes);
  }

  /// Returns a copy of this object.
  ///
  /// Calling [destroy] on the copy does not affect the original object and
  /// vice-versa.
  SecretKeyData copy() {
    return SecretKeyData(
      Uint8List.fromList(bytes),
      overwriteWhenDestroyed: true,
      debugLabel: debugLabel,
    );
  }

  /// Overwrites the bytes with zeroes and discards the reference to them.
  ///
  /// After calling this method, the bytes are no longer accessible and the
  /// getter [bytes] will throw [StateError].
  @override
  void destroy() {
    _bytes.destroy();
    super.destroy();
  }

  @override
  Future<SecretKeyData> extract() async {
    return Future<SecretKeyData>.value(this);
  }

  @override
  String toString() {
    final debugLabel = this.debugLabel;
    if (debugLabel == null) {
      return 'SecretKeyData(...)';
    } else {
      return 'SecretKeyData(..., debugLabel: "$debugLabel")';
    }
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
