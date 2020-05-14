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
    const size = 64;
    print('64-byte message:');
    await _Sign(ed25519, size).report();
    await _SignSync(ed25519, size).report();
    await _Verify(ed25519, size).report();
    await _VerifySync(ed25519, size).report();
    print('');
  }

  {
    const size = 1000000;
    print('1 MB message:');
    await _Sign(ed25519, size).report();
    await _SignSync(ed25519, size).report();
    await _Verify(ed25519, size).report();
    await _VerifySync(ed25519, size).report();
    print('');
  }
}

class _Sign extends SimpleBenchmark {
  final SignatureAlgorithm implementation;
  final int length;

  _Sign(this.implementation, this.length)
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

class _SignSync extends SimpleBenchmark {
  final SignatureAlgorithm implementation;
  final int length;

  _SignSync(this.implementation, this.length)
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

class _Verify extends SimpleBenchmark {
  final SignatureAlgorithm implementation;
  final int length;

  _Verify(this.implementation, this.length)
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

class _VerifySync extends SimpleBenchmark {
  final SignatureAlgorithm implementation;
  final int length;

  _VerifySync(this.implementation, this.length)
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
