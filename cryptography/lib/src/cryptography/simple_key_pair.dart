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

import 'dart:async';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/helpers.dart';
import 'package:meta/meta.dart';

/// A key pair that is made of two simple byte sequences.
///
/// ## Related classes
///   * [SimpleKeyPairData]
///   * [SimplePublicKey]
///
/// ## Algorithms that use this
///   * [Ed25519]
///   * [X25519]
abstract class SimpleKeyPair extends KeyPair {
  factory SimpleKeyPair.lazy(Future<SimpleKeyPair> Function() f) =
      _LazySimpleKeyPair;

  @override
  Future<SimpleKeyPairData> extract();

  Future<List<int>> extractPrivateKeyBytes();

  @override
  Future<SimplePublicKey> extractPublicKey();
}

/// Data of [SimpleKeyPair].
///
/// ## Related classes
///   * [SimpleKeyPair]
///   * [SimplePublicKey]
///
/// ## Algorithms that use this
///   * [Ed25519]
///   * [X25519]
@sealed
class SimpleKeyPairData extends KeyPairData implements SimpleKeyPair {
  final List<int> bytes;

  @override
  final KeyPairType type;

  final FutureOr<SimplePublicKey> _publicKey;

  SimpleKeyPairData(
    this.bytes, {
    required FutureOr<SimplePublicKey> publicKey,
    required this.type,
  })  : _publicKey = publicKey,
        super(type: type);

  @override
  int get hashCode => constantTimeBytesEquality.hash(bytes) ^ type.hashCode;

  @override
  bool operator ==(other) =>
      other is SimpleKeyPairData &&
      constantTimeBytesEquality.equals(bytes, other.bytes) &&
      type == other.type;

  @override
  Future<SimpleKeyPairData> extract() async {
    return Future<SimpleKeyPairData>.value(this);
  }

  @override
  Future<List<int>> extractPrivateKeyBytes() => Future<List<int>>.value(bytes);

  @override
  Future<SimplePublicKey> extractPublicKey() async {
    return _publicKey;
  }

  @override
  String toString() {
    return 'SimpleKeyPairData(..., type: $type)';
  }
}

class _LazySimpleKeyPair extends KeyPair implements SimpleKeyPair {
  Future<SimpleKeyPairData>? _localSecretKeyFuture;
  Future<SimpleKeyPair> Function()? _function;

  _LazySimpleKeyPair(this._function);

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
