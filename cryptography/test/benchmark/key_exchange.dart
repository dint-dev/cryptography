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

import 'package:cryptography_plus/cryptography_plus.dart';

import 'benchmark_helpers.dart';

Future<void> main() async {
  final cryptography = Cryptography.instance;
  await _SharedSecret(cryptography.x25519()).report();
}

class _SharedSecret extends SimpleBenchmark {
  final KeyExchangeAlgorithm implementation;

  late KeyPair keyPair0;

  late KeyPair keyPair1;

  _SharedSecret(this.implementation)
      : super('$implementation.sharedSecretKey(...)');

  @override
  Future<void> run() async {
    await implementation.sharedSecretKey(
      keyPair: keyPair0,
      remotePublicKey: await keyPair1.extractPublicKey(),
    );
  }

  @override
  Future<void> setup() async {
    keyPair0 = await implementation.newKeyPair();
    keyPair1 = await implementation.newKeyPair();
  }
}
