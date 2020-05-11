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

import 'benchmark_helpers.dart';
import 'dart:typed_data';

Future<void> main() async {
  {
    const size = 64;
    print('64-byte message:');
    await SignBenchmark(ed25519, size).report();
    await SignSyncBenchmark(ed25519, size).report();
    await VerifyBenchmark(ed25519, size).report();
    await VerifySyncBenchmark(ed25519, size).report();
    print('');
  }

  {
    const size = 1000000;
    print('1 MB message:');
    await SignBenchmark(ed25519, size).report();
    await SignSyncBenchmark(ed25519, size).report();
    await VerifyBenchmark(ed25519, size).report();
    await VerifySyncBenchmark(ed25519, size).report();
    print('');
  }
}

class SignBenchmark extends SimpleBenchmark {
  final SignatureAlgorithm implementation;
  final int length;

  SignBenchmark(this.implementation, this.length)
      : super('${implementation.name}.sign()');

  List<int> message;
  KeyPair keyPair;

  @override
  void setup() {
    keyPair = implementation.newKeyPairSync();
    message = Uint8List(length);
  }

  @override
  Future<void> run() async {
    final result = await implementation.sign(message, keyPair);
    assert(result != null);
  }
}

class SignSyncBenchmark extends SimpleBenchmark {
  final SignatureAlgorithm implementation;
  final int length;

  SignSyncBenchmark(this.implementation, this.length)
      : super('${implementation.name}.signSync()');

  List<int> message;
  KeyPair keyPair;

  @override
  void setup() {
    keyPair = implementation.newKeyPairSync();
    message = Uint8List(length);
  }

  @override
  void run() {
    final result = implementation.signSync(message, keyPair);
    assert(result != null);
  }
}

class VerifyBenchmark extends SimpleBenchmark {
  final SignatureAlgorithm implementation;
  final int length;

  VerifyBenchmark(this.implementation, this.length)
      : super('${implementation.name}.verify()');

  List<int> message;
  KeyPair keyPair;
  Signature signature;

  @override
  void setup() {
    keyPair = implementation.newKeyPairSync();
    message = Uint8List(length);
    signature = implementation.signSync(message, keyPair);
  }

  @override
  Future<void> run() async {
    final result = await implementation.verify(
      message,
      signature,
    );
    assert(result != null);
  }
}

class VerifySyncBenchmark extends SimpleBenchmark {
  final SignatureAlgorithm implementation;
  final int length;

  VerifySyncBenchmark(this.implementation, this.length)
      : super('${implementation.name}.verifySync()');

  List<int> message;
  KeyPair keyPair;
  Signature signature;

  @override
  void setup() {
    keyPair = implementation.newKeyPairSync();
    message = Uint8List(length);
    signature = implementation.signSync(message, keyPair);
  }

  @override
  void run() {
    final result = implementation.verifySync(
      message,
      signature,
    );
    assert(result != null);
  }
}
