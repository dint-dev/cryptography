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

/// An opaque [KeyPair] that is made of two simple byte sequences.
///
/// The private key bytes of the key may not be in the memory. The private key
/// bytes may not even be extractable. If the private key is in memory, it's an
/// instance of [SimpleKeyPairData].
///
/// The public key is always [SimplePublicKey].
///
/// This class is used with algorithms such as [Ed25519] and [X25519].
abstract class SimpleKeyPair extends KeyPair {
  /// Constructor for subclasses.
  SimpleKeyPair.constructor();

  @Deprecated('This will be removed')
  factory SimpleKeyPair.lazy(Future<SimpleKeyPair> Function() f) =
      _LazySimpleKeyPair;

  @override
  Future<SimpleKeyPairData> extract();

  /// Extracts the private key bytes.
  ///
  /// Throws [UnsupportedError] if the private key bytes are not extractable.
  Future<List<int>> extractPrivateKeyBytes();

  @override
  Future<SimplePublicKey> extractPublicKey();
}

/// An in-memory [SimpleKeyPair] that is made of two simple byte sequences.
///
/// This can be used with algorithms such as [Ed25519] and [X25519].
///
/// If you are no longer using the private key, you should call [destroy] to
/// overwrite the private key bytes with zeros and prevent the private key from
/// being used in the future.
@sealed
class SimpleKeyPairData extends KeyPairData implements SimpleKeyPair {
  final SensitiveBytes _bytes;
  final String? debugLabel;

  @override
  final SimplePublicKey publicKey;

  SimpleKeyPairData(
    List<int> bytes, {
    required this.publicKey,
    required super.type,
    this.debugLabel,
  }) : _bytes = SensitiveBytes(bytes);

  /// Private key bytes.
  ///
  /// The bytes are destroyed when [destroy] is called.
  /// After that, this getter throws [StateError].
  List<int> get bytes {
    final bytes = _bytes;
    if (bytes.hasBeenDestroyed) {
      throw _destroyedError();
    }
    return bytes;
  }

  @override
  bool get hasBeenDestroyed => _bytes.hasBeenDestroyed;

  @override
  int get hashCode => publicKey.hashCode ^ type.hashCode;

  @override
  bool operator ==(other) =>
      other is SimpleKeyPairData &&
      publicKey == other.publicKey &&
      type == other.type;

  /// Returns a copy of this object.
  ///
  /// The copy is not affected by [destroy].
  @override
  SimpleKeyPairData copy() {
    if (hasBeenDestroyed) {
      throw StateError('Private key has been destroyed');
    }
    final bytes = _bytes;
    if (bytes.hasBeenDestroyed) {
      throw _destroyedError();
    }
    return SimpleKeyPairData(
      Uint8List.fromList(bytes),
      publicKey: publicKey,
      type: type,
      debugLabel: debugLabel,
    );
  }

  @override
  void destroy() {
    super.destroy();
    _bytes.destroy();
  }

  @override
  Future<SimpleKeyPairData> extract() async {
    if (hasBeenDestroyed) {
      throw StateError('Private key has been destroyed');
    }
    return this;
  }

  @override
  Future<List<int>> extractPrivateKeyBytes() async {
    if (hasBeenDestroyed) {
      throw StateError('Private key has been destroyed');
    }
    return bytes;
  }

  @override
  Future<SimplePublicKey> extractPublicKey() async {
    return publicKey;
  }

  @override
  String toString() {
    final debugLabel = this.debugLabel;
    if (debugLabel == null) {
      return 'SimpleKeyPairData(..., publicKey: $publicKey)';
    } else {
      return 'SimpleKeyPairData(..., publicKey: $publicKey, debugLabel: "$debugLabel")';
    }
  }

  StateError _destroyedError() {
    return StateError('$this has been destroyed.');
  }
}

class _LazySimpleKeyPair extends SimpleKeyPair {
  Future<SimpleKeyPairData>? _localSecretKeyFuture;
  Future<SimpleKeyPair> Function()? _function;

  _LazySimpleKeyPair(this._function) : super.constructor();

  @override
  Future<SimpleKeyPairData> extract() {
    final function = _function;
    if (function != null) {
      _localSecretKeyFuture = function().then((value) {
        if (value is SimpleKeyPairData) {
          return value;
        }
        return value.extract();
      });
      _function = null;
    }
    final localSecretKeyFuture = _localSecretKeyFuture;
    if (localSecretKeyFuture == null) {
      throw Error();
    }
    return localSecretKeyFuture;
  }

  @override
  Future<List<int>> extractPrivateKeyBytes() {
    return extract().then((value) => value.bytes);
  }

  @override
  Future<SimplePublicKey> extractPublicKey() {
    return extract().then((value) => value.extractPublicKey());
  }
}
