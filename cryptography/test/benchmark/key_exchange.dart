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

import 'package:cryptography/cryptography.dart';

import 'common.dart';

void main() {
  SharedSecretBenchmark(x25519).report();
}

class SharedSecretBenchmark extends ThroughputBenchmarkBase {
  final KeyExchangeAlgorithm implementation;

  SharedSecretBenchmark(this.implementation)
      : super('Shared secret with ${implementation.name}');

  KeyPair keypair1;
  KeyPair keypair2;

  @override
  void setup() {
    keypair1 = implementation.newKeyPairSync();
    keypair2 = implementation.newKeyPairSync();
  }

  @override
  void run() {
    implementation.sharedSecretSync(
      localPrivateKey: keypair1.privateKey,
      remotePublicKey: keypair2.publicKey,
    );
  }
}
