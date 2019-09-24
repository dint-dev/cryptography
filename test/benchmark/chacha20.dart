// Copyright 2019 Gohilla (opensource@gohilla.com).
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

import 'package:benchmark_harness/benchmark_harness.dart';
import 'package:cryptography/cryptography.dart';

const million = 1000000;

void main() {
  print("Benchmarks:");
  print("--");
  Chacha20StreamBenchmark(million).report();
  print("--");
  Chacha20NumerousSmallMessagesBenchmark(million, 100).report();
  print("--");
}

class Chacha20StreamBenchmark extends BenchmarkBase {
  final int totalLength;
  SecretKey secretKey;
  SecretKey nonce;
  Uint8List cleartext;
  Uint8List result;

  Chacha20StreamBenchmark(this.totalLength)
      : super("${totalLength ~/ million} MB stream");

  @override
  void setup() {
    // 100 MB cleartext
    cleartext = Uint8List(totalLength);
    for (var i = 0; i < cleartext.lengthInBytes; i++) {
      cleartext[i] = 0xFF & i;
    }
    secretKey = chacha20.newSecretKey();
    nonce = chacha20.newNonce();
    result = Uint8List(cleartext.length);
  }

  @override
  void run() {
    chacha20
        .newState(secretKey, nonce: nonce)
        .fillWithConverted(result, 0, cleartext, 0);
  }

  @override
  void exercise() {
    run();
  }
}

class Chacha20NumerousSmallMessagesBenchmark extends BenchmarkBase {
  final int totalLength;
  final int messageLength;
  SecretKey secretKey;
  SecretKey nonce;
  Uint8List cleartext;
  Uint8List result;

  Chacha20NumerousSmallMessagesBenchmark(this.totalLength, this.messageLength)
      : super(
            "${totalLength ~/ million} MB in ${messageLength} byte long messages");

  @override
  void setup() {
    cleartext = Uint8List(messageLength);
    for (var i = 0; i < cleartext.lengthInBytes; i++) {
      cleartext[i] = 0xFF & i;
    }
    secretKey = chacha20.newSecretKey();
    nonce = chacha20.newNonce();
    result = Uint8List(cleartext.lengthInBytes);
  }

  @override
  void run() {
    final state = chacha20.newState(secretKey, nonce: nonce);
    state.fillWithConverted(result, 0, cleartext, 0);
  }

  @override
  void exercise() {
    for (var i = 0; i < totalLength ~/ messageLength; i++) {
      run();
    }
  }
}
