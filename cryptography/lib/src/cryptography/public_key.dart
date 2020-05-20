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

import 'package:collection/collection.dart';
import 'package:cryptography/cryptography.dart';

/// A public key of some [KeyPair].
///
/// For examples of usage, see [KeyExchangeAlgorithm] and [SignatureAlgorithm].
abstract class PublicKey {
  /// Bytes of the public key.
  List<int> get bytes;

  Map<Object, Object> _cachedValues;

  factory PublicKey(List<int> bytes) = _PublicKey;

  /// A constructor for subclasses.
  PublicKey.constructor();

  /// Used internally by _package:cryptography_ for caching cryptographic
  /// objects such as Web Cryptography _CryptoKey_ references.
  Map<Object, Object> get cachedValues => _cachedValues ??= <Object, Object>{};

  @override
  int get hashCode {
    return const ListEquality<int>().hash(bytes);
  }

  @override
  bool operator ==(other) {
    return other is PublicKey &&
        const ListEquality<int>().equals(bytes, other.bytes);
  }

  @override
  String toString() {
    return "PublicKey([${bytes.join(', ')}])";
  }
}

class _PublicKey extends PublicKey {
  @override
  final List<int> bytes;

  _PublicKey(this.bytes)
      : assert(bytes != null),
        super.constructor();
}
