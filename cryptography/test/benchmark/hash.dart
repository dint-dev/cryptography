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

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'benchmark_helpers.dart';

Future<void> main() async {
  {
    print('64 byte messages:');
    const size = 64;
    await HashBenchmark(sha256, size).report();
    await HashSyncBenchmark(sha256, size).report();
    await HashBenchmark(sha512, size).report();
    await HashSyncBenchmark(sha512, size).report();
    await HashBenchmark(blake2s, size).report();
    await HashSyncBenchmark(blake2s, size).report();
    print('');
  }

  {
    const size = 1000;
    print('1 kB messages:');
    await HashBenchmark(sha256, size).report();
    await HashSyncBenchmark(sha256, size).report();
    await HashBenchmark(sha512, size).report();
    await HashSyncBenchmark(sha512, size).report();
    await HashBenchmark(blake2s, size).report();
    await HashSyncBenchmark(blake2s, size).report();
    print('');
  }

  {
    const size = 1000000;
    print('1 MB messages:');
    await HashBenchmark(sha256, size).report();
    await HashSyncBenchmark(sha256, size).report();
    await HashBenchmark(sha512, size).report();
    await HashSyncBenchmark(sha512, size).report();
    await HashBenchmark(blake2s, size).report();
    await HashSyncBenchmark(blake2s, size).report();
  }
}

class HashBenchmark extends SimpleBenchmark {
  final HashAlgorithm implementation;
  final int length;

  List<int> message;

  HashBenchmark(this.implementation, this.length)
      : super('${implementation.name}'.padRight(20));

  @override
  Future<void> run() {
    return implementation.hash(message);
  }

  @override
  void setup() {
    message = Uint8List(length);
  }
}

class HashSyncBenchmark extends SimpleBenchmark {
  final HashAlgorithm implementation;
  final int length;

  List<int> message;

  HashSyncBenchmark(this.implementation, this.length)
      : super('${implementation.name} (sync)'.padRight(20));

  @override
  void run() {
    implementation.hashSync(message);
  }

  @override
  void setup() {
    message = Uint8List(length);
  }
}
