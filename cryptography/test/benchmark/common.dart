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

import 'package:benchmark_harness/benchmark_harness.dart';

/// A helper for "N op per second" benchmarks.
abstract class ThroughputBenchmarkBase extends BenchmarkBase {
  int runCount = 0;

  ThroughputBenchmarkBase(String description)
      : super(description, emitter: _ThroughputEmitter());

  @override
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
    print('$testName: $times op / second');
  }
}
