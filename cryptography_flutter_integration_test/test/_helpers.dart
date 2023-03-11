import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';

Future<Duration> time(Future<void> Function() f, {required int count}) async {
  // Try to clear other event handling by waiting a bit.
  await Future.delayed(const Duration(milliseconds: 100));

  final watch = Stopwatch()..start();
  final futures = <Future>[];
  for (var i = 0; i < count; i++) {
    futures.add(f());
  }
  await Future.wait(futures);
  watch.stop();
  return watch.elapsed;
}

String sizeString(int n) {
  if (n < 1000) {
    return '$n';
  } else if (n < 1000 * 1000) {
    return '${n ~/ 1000}KB';
  } else {
    return '${n ~/ (1000 * 1000)}MB';
  }
}

String amountString(int n) {
  if (n < 1000) {
    return '$n';
  } else if (n < 1000 * 1000) {
    return '${n ~/ 1000}K';
  } else {
    return '${n ~/ (1000 * 1000)}M';
  }
}

Future<void> expectFasterThanPureDart({
  required String? description,
  required Object dartObject,
  required Object benchmarkedObject,
  required Future<void> Function() dart,
  required Future<void> Function() benchmarked,
  required double maxRelativeLatency,
  int n = 10,
  int attempts = 1,
}) async {
  for (var i = 0; i < attempts; i++) {
    printOnFailure('----');
    final dartTime = await time(dart, count: n);
    printOnFailure('Attempt #$i: $dartObject: $dartTime');

    final flutterTime = await time(benchmarked, count: n);
    printOnFailure('Attempt #$i: $benchmarkedObject: $flutterTime');

    final relativeTime = flutterTime.inMicroseconds / dartTime.inMicroseconds;
    expect(
      relativeTime,
      lessThan(maxRelativeLatency),
      reason:
          '$description: $benchmarkedObject relative to $dartObject (${dartTime.inMicroseconds} us) should be under $maxRelativeLatency.',
    );

    if (i == 0) {
      if (kDebugMode) {
        final baseline =
            timeString(dartTime, sameUnitAs: flutterTime).padLeft(10);
        final optimized = timeString(flutterTime).padLeft(10);
        print('${'  $description:'.padRight(40)}\n'
            '      ${relativeTime.toStringAsFixed(3)} * baseline\n'
            '      optimized: $optimized\n'
            '      baseline:  $baseline');
      }
    }
  }
}

String timeString(Duration duration, {Duration? sameUnitAs}) {
  sameUnitAs ??= duration;
  if (sameUnitAs < const Duration(seconds: 1)) {
    return '${(duration.inMicroseconds / 1000).toStringAsFixed(1)} ms';
  }
  return '${(duration.inMilliseconds / 1000).toStringAsFixed(1)} s';
}
