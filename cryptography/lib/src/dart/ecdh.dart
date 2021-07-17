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

/// A stub for [Ecdh] (P256, P384, P521) implemented in pure Dart.
class DartEcdh extends Ecdh {
  @override
  final KeyPairType keyPairType;

  DartEcdh.p256() : this._(KeyPairType.p256);

  DartEcdh.p384() : this._(KeyPairType.p384);

  DartEcdh.p521() : this._(KeyPairType.p521);

  DartEcdh._(this.keyPairType) : super.constructor();

  @override
  Future<EcKeyPair> newKeyPair() {
    throw UnimplementedError();
  }

  @override
  Future<EcKeyPair> newKeyPairFromSeed(List<int> seed) {
    throw UnimplementedError();
  }

  @override
  Future<SecretKey> sharedSecretKey({
    required KeyPair keyPair,
    required PublicKey remotePublicKey,
  }) {
    throw UnimplementedError();
  }
}
