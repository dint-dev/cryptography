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

import 'dart:typed_data';

import 'package:cryptography_plus/cryptography_plus.dart';

import 'benchmark_helpers.dart';

Future<void> main() async {
  final cryptography = Cryptography.instance;
  {
    const size = 100;
    const times = 10000;
    print('100 byte messages $times times:');
    await _Hash(cryptography.sha256(), size, times).report();
    await _Hash(cryptography.sha512(), size, times).report();
    await _Hash(cryptography.blake2s(), size, times).report();
    await _Hash(cryptography.blake2b(), size, times).report();
    print('');
  }

  {
    const size = 1000;
    const times = 1000;
    print('1 kB messages $times times:');
    await _Hash(cryptography.sha256(), size, times).report();
    await _Hash(cryptography.sha512(), size, times).report();
    await _Hash(cryptography.blake2s(), size, times).report();
    await _Hash(cryptography.blake2b(), size, times).report();
    print('');
  }

  {
    const size = 1000000;
    const times = 1;
    print('1 MB messages $times times:');
    await _Hash(cryptography.sha256(), size, times).report();
    await _Hash(cryptography.sha512(), size, times).report();
    await _Hash(cryptography.blake2s(), size, times).report();
    await _Hash(cryptography.blake2b(), size, times).report();
  }
}

class _Hash extends SimpleBenchmark {
  final HashAlgorithm implementation;
  final int length;
  final int n;
  late List<int> message;

  _Hash(this.implementation, this.length, this.n)
      : super('$implementation.hash(...)'.padRight(20));

  @override
  Future<void> run() async {
    final futures = <Future>[];
    for (var i = 0; i < n; i++) {
      futures.add(implementation.hash(message));
    }
    await Future.wait(futures);
  }

  @override
  void setup() {
    message = Uint8List(length);
  }
}
