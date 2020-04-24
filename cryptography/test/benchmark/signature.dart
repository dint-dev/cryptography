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
  SignBenchmark(ed25519).report();
  VerifyBenchmark(ed25519).report();
}

class SignBenchmark extends ThroughputBenchmarkBase {
  final SignatureAlgorithm implementation;

  SignBenchmark(this.implementation)
      : super('Signing with ${implementation.name}');

  List<int> message;
  KeyPair keyPair;
  Signature signature;

  @override
  void setup() {
    keyPair = implementation.newKeyPairSync();
    message = [1, 2, 3];
  }

  @override
  void run() {
    signature = implementation.signSync(message, keyPair);
  }
}

class VerifyBenchmark extends ThroughputBenchmarkBase {
  final SignatureAlgorithm implementation;

  VerifyBenchmark(this.implementation)
      : super('Verifying signature with ${implementation.name}');

  List<int> message;
  KeyPair keyPair;
  Signature signature;

  @override
  void setup() {
    keyPair = implementation.newKeyPairSync();
    message = [1, 2, 3];
    signature = implementation.signSync(message, keyPair);
  }

  @override
  void run() {
    implementation.verifySync(
      message,
      signature,
    );
  }
}
