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
  // 1 MB
  await _Argon2(memory: 1000, parallelism: 1).report();
  await _Argon2(memory: 1000, parallelism: 10).report();

  // 10 MB
  await _Argon2(memory: 10000, parallelism: 1).report();
  await _Argon2(memory: 10000, parallelism: 10).report();

  // 25 MB
  await _Argon2(memory: 25000, parallelism: 1).report();
  await _Argon2(memory: 25000, parallelism: 10).report();

  // 100 MB
  await _Argon2(memory: 100000, parallelism: 1).report();
  await _Argon2(memory: 100000, parallelism: 10).report();
}

class _Argon2 extends SimpleBenchmark {
  final int memory;
  final int parallelism;

  _Argon2({required this.memory, required this.parallelism})
      : super(
            '$Argon2id(memory: ${memory ~/ 1000} MB, parallelism: $parallelism, ...)');

  @override
  Future<void> run() async {
    await Argon2id(
      memory: memory,
      parallelism: parallelism,
      iterations: 1,
      hashLength: 32,
    ).deriveKeyFromPassword(password: '', nonce: const []);
  }
}
