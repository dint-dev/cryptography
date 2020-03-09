// Copyright 2019 Gohilla Ltd (https://gohilla.com).
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
import 'package:meta/meta.dart';

/// A cryptographic signature. Typically the signer creates the signature with
/// its private key and the recipient verifies the signature using the signer's
/// public key.
class Signature {
  final List<int> bytes;
  final PublicKey publicKey;

  const Signature(this.bytes, {@required this.publicKey})
      : assert(bytes != null),
        assert(publicKey != null);

  @override
  int get hashCode =>
      const ListEquality<int>().hash(bytes) ^ publicKey.hashCode;

  @override
  bool operator ==(other) =>
      other is Signature &&
      const ListEquality<int>().equals(bytes, other.bytes) &&
      publicKey == other.publicKey;

  @override
  String toString() => 'Signature(...)';
}

/// Superclass for signature-generating algorithms.
abstract class SignatureAlgorithm {
  const SignatureAlgorithm();

  KeyPairGenerator get keyPairGenerator;

  String get name;

  Future<Signature> sign(List<int> input, KeyPair keyPair) {
    return Future<Signature>(() => signSync(input, keyPair));
  }

  Signature signSync(List<int> input, KeyPair keyPair);

  Future<bool> verify(List<int> input, Signature signature) {
    return Future<bool>(() => verifySync(input, signature));
  }

  bool verifySync(List<int> input, Signature signature);
}
