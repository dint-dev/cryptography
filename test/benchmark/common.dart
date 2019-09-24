import 'package:benchmark_harness/benchmark_harness.dart';

/// A helper for "N op per second" benchmarks.
abstract class ThroughputBenchmarkBase extends BenchmarkBase {
  int runCount = 0;

  ThroughputBenchmarkBase(String description)
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
