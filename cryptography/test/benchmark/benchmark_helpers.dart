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

import 'dart:async';

/// A helper for "N op per second" benchmarks.
abstract class SimpleBenchmark {
  final String _name;

  SimpleBenchmark(this._name);

  Future<void> report() async {
    await setup();
    try {
      await warmup();
      var watch = Stopwatch();
      watch.start();
      var n = 0;
      while (watch.elapsedMilliseconds < 200) {
        final possibleFuture = run();
        if (possibleFuture is Future) {
          await possibleFuture;
        }
        n++;
      }
      watch.stop();

      n = (n * (1000000 / watch.elapsed.inMicroseconds)).ceil();
      final prefix = '$_name:'.padRight(32, ' ');
      print('$prefix $n op / second');
    } finally {
      await teardown();
    }
  }

  FutureOr<void> run();

  FutureOr<void> setup() {}

  FutureOr<void> teardown() {}

  FutureOr<void> warmup() async {
    for (var i = 0; i < 5; i++) {
      await run();
    }
  }
}
