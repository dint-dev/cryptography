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
    print('100 byte messages:');
    const size = 100;
    const times = 10000;
    await _Hash(sha256, size, times).report();
    await _HashSync(sha256, size, times).report();
    await _Hash(sha512, size, times).report();
    await _HashSync(sha512, size, times).report();
    await _Hash(blake2s, size, times).report();
    await _HashSync(blake2s, size, times).report();
    print('');
  }

  {
    const size = 1000;
    const times = 1000;
    print('1 kB messages:');
    await _Hash(sha256, size, times).report();
    await _HashSync(sha256, size, times).report();
    await _Hash(sha512, size, times).report();
    await _HashSync(sha512, size, times).report();
    await _Hash(blake2s, size, times).report();
    await _HashSync(blake2s, size, times).report();
    print('');
  }

  {
    const size = 1000000;
    const times = 1;
    print('1 MB messages:');
    await _Hash(sha256, size, times).report();
    await _HashSync(sha256, size, times).report();
    await _Hash(sha512, size, times).report();
    await _HashSync(sha512, size, times).report();
    await _Hash(blake2s, size, times).report();
    await _HashSync(blake2s, size, times).report();
  }
}

class _Hash extends SimpleBenchmark {
  final HashAlgorithm implementation;
  final int length;
  final int n;
  List<int> message;

  _Hash(this.implementation, this.length, this.n)
      : super('${implementation.name}'.padRight(20));

  @override
  Future<void> run() async {
    for (var i = 0; i < n; i++) {
      await implementation.hash(message);
    }
  }

  @override
  void setup() {
    message = Uint8List(length);
  }
}

class _HashSync extends SimpleBenchmark {
  final HashAlgorithm implementation;
  final int length;
  final int n;
  List<int> message;

  _HashSync(this.implementation, this.length, this.n)
      : super('${implementation.name} (sync)'.padRight(20));

  @override
  void run() {
    for (var i = 0; i < n; i++) {
      implementation.hashSync(message);
    }
  }

  @override
  void setup() {
    message = Uint8List(length);
  }
}
