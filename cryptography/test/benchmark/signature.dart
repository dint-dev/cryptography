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
    const size = 64;
    print('64-byte message:');
    await _Sign(cryptography.ed25519(), size).report();
    await _Verify(cryptography.ed25519(), size).report();
    print('');
  }

  {
    const size = 1000000;
    print('1 MB message:');
    await _Sign(cryptography.ed25519(), size).report();
    await _Verify(cryptography.ed25519(), size).report();
    print('');
  }
}

class _Sign extends SimpleBenchmark {
  final SignatureAlgorithm implementation;
  final int length;

  late List<int> message;

  late KeyPair keyPair;

  _Sign(this.implementation, this.length) : super('$implementation.sign(...)');

  @override
  Future<void> run() async {
    await implementation.sign(
      message,
      keyPair: keyPair,
    );
  }

  @override
  Future<void> setup() async {
    message = Uint8List(length);
    keyPair = await implementation.newKeyPair();
  }
}

class _Verify extends SimpleBenchmark {
  final SignatureAlgorithm implementation;
  final int length;

  late List<int> message;

  late KeyPair keyPair;
  late Signature signature;

  _Verify(this.implementation, this.length)
      : super('$implementation.verify(...)');

  @override
  Future<void> run() async {
    await implementation.verify(
      message,
      signature: signature,
    );
  }

  @override
  Future<void> setup() async {
    keyPair = await implementation.newKeyPair();
    message = Uint8List(length);
    signature = await implementation.sign(message, keyPair: keyPair);
  }
}
