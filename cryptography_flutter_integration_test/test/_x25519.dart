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
import 'package:cryptography_test/algorithms/x25519.dart' as shared;
import 'package:flutter_test/flutter_test.dart';

import '_helpers.dart';

void testX25519() {
  shared.testX25519();

  const dartAlgorithm = DartX25519();
  final defaultAlgorithm = X25519();
  const count = 10;

  test(
      '${defaultAlgorithm.runtimeType}.newKeyPair(...): $count times, NOT MUCH SLOWER than the pure Dart implementation',
      () async {
    await expectFasterThanPureDart(
      description: 'When n=$count',
      dart: () => dartAlgorithm.newKeyPair(),
      dartObject: dartAlgorithm,
      benchmarked: () => defaultAlgorithm.newKeyPair(),
      benchmarkedObject: defaultAlgorithm,
      maxRelativeLatency: 4.0,
      n: count,
    );
  });

  test(
      '${defaultAlgorithm.runtimeType}.sharedSecretKey(...): $count times, NOT MUCH SLOWER than the pure Dart implementation',
      () async {
    final keyPair = await defaultAlgorithm.newKeyPair();
    final peerPublicKey =
        await (await defaultAlgorithm.newKeyPair()).extractPublicKey();

    await expectFasterThanPureDart(
      description: 'When n=$count',
      dart: () => dartAlgorithm.sharedSecretKey(
        keyPair: keyPair,
        remotePublicKey: peerPublicKey,
      ),
      dartObject: dartAlgorithm,
      benchmarked: () => defaultAlgorithm.sharedSecretKey(
        keyPair: keyPair,
        remotePublicKey: peerPublicKey,
      ),
      benchmarkedObject: defaultAlgorithm,
      maxRelativeLatency: 4.0,
      n: count,
    );
  });
}
