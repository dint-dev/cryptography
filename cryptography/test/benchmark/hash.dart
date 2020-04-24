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

import 'package:cryptography/cryptography.dart';

import 'common.dart';
import 'dart:typed_data';

void main() {
  HashBenchmark(sha256).report();
  HashBenchmark(sha512).report();
  HashBenchmark(blake2s).report();
}

class HashBenchmark extends ThroughputBenchmarkBase {
  final HashAlgorithm implementation;

  HashBenchmark(this.implementation)
      : super('${implementation.name.padRight(12)}');

  List<int> message;

  @override
  void setup() {
    message = Uint8List(1024);
  }

  @override
  void run() {
    implementation.hash(message);
  }
}
