// Copyright 2023 Gohilla.
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
  await _Benchmark(Pbkdf2.hmacSha256(iterations: 100000, bits: 128)).report();
}

class _Benchmark extends SimpleBenchmark {
  final Pbkdf2 implementation;

  _Benchmark(this.implementation) : super('$implementation.deriveKey(...)');

  @override
  Future<void> run() async {
    await implementation.deriveKey(
      secretKey: SecretKey([1, 2, 3]),
      nonce: [4, 5, 6],
    );
  }
}
