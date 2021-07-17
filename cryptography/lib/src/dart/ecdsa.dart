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
// For specification, see the License for the specific language governing permissions and
// limitations under the License.

import 'package:cryptography/cryptography.dart';

/// A stub for [Ecdsa] (P256, P384, P521) implemented in pure Dart.
class DartEcdsa extends Ecdsa {
  @override
  final KeyPairType keyPairType;

  @override
  final HashAlgorithm hashAlgorithm;

  DartEcdsa.p256(HashAlgorithm hashAlgorithm)
      : this._(KeyPairType.p256, hashAlgorithm);

  DartEcdsa.p384(HashAlgorithm hashAlgorithm)
      : this._(KeyPairType.p384, hashAlgorithm);

  DartEcdsa.p521(HashAlgorithm hashAlgorithm)
      : this._(KeyPairType.p521, hashAlgorithm);

  DartEcdsa._(
    this.keyPairType,
    this.hashAlgorithm,
  ) : super.constructor();

  @override
  Future<EcKeyPair> newKeyPair() {
    throw UnimplementedError();
  }

  @override
  Future<EcKeyPair> newKeyPairFromSeed(List<int> seed) {
    throw UnimplementedError();
  }

  @override
  Future<Signature> sign(
    List<int> message, {
    required KeyPair keyPair,
    PublicKey? publicKey,
  }) async {
    throw UnimplementedError();
  }

  @override
  Future<bool> verify(
    List<int> message, {
    required Signature signature,
  }) async {
    throw UnimplementedError();
  }
}
