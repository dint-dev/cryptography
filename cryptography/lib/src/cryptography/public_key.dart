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

/// Public key part of [KeyPair].
///
/// An example of obtaining a public key:
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// void main() {
///   final keyPair = x25519.newKeyPairSync();
///   final publicKey = keyPair.privateKey;
/// }
/// ```
class PublicKey {
  /// Bytes of the public key.
  final List<int> bytes;

  const PublicKey(this.bytes) : assert(bytes != null);

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
