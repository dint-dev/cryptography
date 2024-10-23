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

import 'dart:math';

import 'package:cryptography_plus/cryptography_plus.dart';

import 'benchmark_helpers.dart';

Future<void> main() async {
  const times = 1 << 16;
  await _Random(SecureRandom.fast, times).report();
  await _Random(SecureRandom.safe, times).report();
}

class _Random extends SimpleBenchmark {
  final Random random;
  final int n;

  _Random(this.random, this.n)
      : super('$random.nextInt(...), $n times'.padRight(20));

  @override
  Future<void> run() async {
    for (var i = 0; i < n; i++) {
      random.nextInt(0x100000000);
    }
  }
}
