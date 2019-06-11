// Copyright 2019 terrier989 <terrier989@gmail.com>.
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

import 'package:benchmark_harness/benchmark_harness.dart';
import 'package:curve25519/curve25519.dart';

void main() {
  X25519Benchmark().report();
}

class X25519Benchmark extends _ThroughputBenchmarkBase {
  final X25519 implementation;

  X25519Benchmark({this.implementation = const X25519()})
      : super("Calculating shared secret");

  AsymmetricKeyPair keypair1;
  AsymmetricKeyPair keypair2;

  @override
  void setup() {
    keypair1 = implementation.generateKeyPairSync();
    keypair2 = implementation.generateKeyPairSync();
  }

  @override
  void run() {
    implementation.calculateSharedSecretSync(
      keypair1.secretKey,
      keypair2.publicKey,
    );
  }
}

/// A helper for "N op per second" benchmarks.
abstract class _ThroughputBenchmarkBase extends BenchmarkBase {
  int runCount = 0;

  _ThroughputBenchmarkBase(String description)
      : super(description, emitter: _ThroughputEmitter());

  void run();

  @override
  void exercise() {
    runCount = 0;

    final endAt = DateTime.now().add(const Duration(seconds: 1));
    while (DateTime.now().isBefore(endAt)) {
      run();
      runCount++;
    }
    (emitter as _ThroughputEmitter).times = runCount;
  }
}

class _ThroughputEmitter extends ScoreEmitter {
  int times;

  @override
  void emit(String testName, double value) {
    print("$testName: $times op / second");
  }
}
