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

/// An opaque [KeyPair] that is made of two simple byte sequences.
///
/// The private key bytes of the key may not be in the memory. The private key
/// bytes may not even be extractable. If the private key is in memory, it's an
/// instance of [SimpleKeyPairData].
///
/// The public key is always [SimplePublicKeyData].
///
/// This class is used with algorithms such as [Ed25519] and [X25519].
abstract class SimpleKeyPair extends KeyPair {
  factory SimpleKeyPair.lazy(Future<SimpleKeyPair> Function() f) =
      _LazySimpleKeyPair;

  @override
  Future<SimpleKeyPairData> extract();

  Future<List<int>> extractPrivateKeyBytes();

  @override
  Future<SimplePublicKey> extractPublicKey();
}

/// An in-memory [SimpleKeyPair] that is made of two simple byte sequences.
///
/// This can be used with algorithms such as [Ed25519] and [X25519].
@sealed
class SimpleKeyPairData implements KeyPairData, SimpleKeyPair {
  final List<int> bytes;

  @override
  final KeyPairType type;

  final FutureOr<SimplePublicKey> _publicKey;

  SimpleKeyPairData(
    this.bytes, {
    required FutureOr<SimplePublicKey> publicKey,
    required this.type,
  }) : _publicKey = publicKey;

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
