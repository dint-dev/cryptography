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

import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:cryptography_plus/dart.dart';
import 'package:cryptography_test/algorithms/ed25519.dart' as shared;
import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';

import '_helpers.dart';

void testEd25519() {
  shared.testEd25519();

  final dartAlgorithm = DartEd25519();
  final defaultAlgorithm = Ed25519();

  test(
      '${defaultAlgorithm.runtimeType}: newKeyPair(...): NOT MUCH SLOWER than the pure Dart implementation',
      () async {
    const n = 10;
    await expectFasterThanPureDart(
      description: 'When n=$n',
      dart: () => dartAlgorithm.newKeyPair(),
      dartObject: dartAlgorithm,
      benchmarked: () => defaultAlgorithm.newKeyPair(),
      benchmarkedObject: defaultAlgorithm,
      maxRelativeLatency: 3.0,
      n: n,
    );
  });

  test(
      '${defaultAlgorithm.runtimeType}: sign(...): NOT MUCH SLOWER than the pure Dart implementation, 100 bytes',
      () async {
    final data = Uint8List(100);
    final dartKeyPair = await dartAlgorithm.newKeyPair();
    final flutterKeyPair = await defaultAlgorithm.newKeyPair();

    const n = 10;
    await expectFasterThanPureDart(
      description: 'When data is 100 bytes, n=$n',
      dart: () => dartAlgorithm.sign(data, keyPair: dartKeyPair),
      dartObject: dartAlgorithm,
      benchmarked: () => defaultAlgorithm.sign(data, keyPair: flutterKeyPair),
      benchmarkedObject: defaultAlgorithm,
      maxRelativeLatency: 4.0,
      n: n,
    );
  });

  test(
      '${defaultAlgorithm.runtimeType}: sign(...): NOT MUCH SLOWER than the pure Dart implementation, 1 megabyte',
      () async {
    final data = Uint8List(1000 * 1000);
    final dartKeyPair = await dartAlgorithm.newKeyPair();
    final flutterKeyPair = await defaultAlgorithm.newKeyPair();

    const n = 10;
    await expectFasterThanPureDart(
      description: 'When data is 1 MB, n=$n',
      dart: () => dartAlgorithm.sign(data, keyPair: dartKeyPair),
      dartObject: dartAlgorithm,
      benchmarked: () => defaultAlgorithm.sign(data, keyPair: flutterKeyPair),
      benchmarkedObject: defaultAlgorithm,
      maxRelativeLatency: 4.0,
      n: n,
    );
  });
}
