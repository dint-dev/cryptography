// Copyright 2023 Gohilla.
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

/// Test utilities for [KeyExchangeAlgorithm] classes.
///
/// ## Example
/// See [testKeyExchangeAlgorithm].
library cryptography_plus_test.key_exchange_algorithm;

import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:cryptography_plus/dart.dart';
import 'package:test/test.dart';

import 'hex.dart';

KeyExchangeAlgorithm? _keyExchangeAlgorithm;

/// Currently tested [KeyExchangeAlgorithm].
KeyExchangeAlgorithm get keyExchangeAlgorithm => _keyExchangeAlgorithm!;

/// Test a [KeyExchangeAlgorithm].
///
/// ## Example
/// ```dart
/// import 'package:cryptography_test/key_exchange.dart';
///
/// void main() {
///   testKeyExchangeAlgorithm(
///     builder: () => MyAlgorithm(),
///     otherTests: () {
///       test('something', () {
///         // ...
///       });
///     },
///   );
/// }
/// ```
void testKeyExchangeAlgorithm({
  required KeyExchangeAlgorithm Function() builder,
  bool Function()? skip,
  DartKeyExchangeAlgorithmMixin? dartAlgorithm,
  required void Function()? otherTests,
}) {
  try {
    builder().newKeyPair();
  } on UnimplementedError {
    return;
  }
  group('${builder()}:', () {
    // Is there are a way to skip tests inside 'setUp'?
    // markTestSkipped(message) didn't seem to work.
    if (skip?.call() == true) {
      return;
    }

    setUp(() {
      _keyExchangeAlgorithm = builder();
    });
    tearDown(() {
      _keyExchangeAlgorithm = null;
    });

    test('newKeyPair(...) returns unique, valid keys', () async {
      // Compute key pairs using the platform implementation
      final keyPair0 = await keyExchangeAlgorithm.newKeyPair();
      final keyPair1 = await keyExchangeAlgorithm.newKeyPair();
      if (keyExchangeAlgorithm is X25519) {
        keyPair0 as SimpleKeyPairData;
        keyPair1 as SimpleKeyPairData;
        expect(keyPair0.bytes, hasLength(32));
        expect(keyPair1.bytes, hasLength(32));
        expect(keyPair0.bytes, isNot(keyPair1.bytes));
      }

      final publicKey0 = await keyPair0.extractPublicKey();
      final publicKey1 = await keyPair1.extractPublicKey();
      if (keyExchangeAlgorithm is X25519) {
        publicKey0 as SimplePublicKey;
        publicKey1 as SimplePublicKey;
        expect(publicKey0.bytes, hasLength(32));
        expect(publicKey1.bytes, hasLength(32));
        expect(publicKey0.bytes, isNot(publicKey1.bytes));
      }

      // Validate using the pure Dart implementation
      final referenceImplementation = dartAlgorithm ?? keyExchangeAlgorithm;
      final secretKey0 = await referenceImplementation.sharedSecretKey(
        keyPair: keyPair0,
        remotePublicKey: publicKey1,
      );
      final secretKey1 = await referenceImplementation.sharedSecretKey(
        keyPair: keyPair1,
        remotePublicKey: publicKey0,
      );
      expect(
        hexFromBytes(await secretKey0.extractBytes()),
        hexFromBytes(await secretKey1.extractBytes()),
        reason: 'Secrets must be equal.',
      );
    });

    test('sharedSecretKey(...): both parties compute the same secret',
        () async {
      // Create key pairs using the pure Dart implementation
      final referenceImplementation = dartAlgorithm ?? keyExchangeAlgorithm;
      final aliceKeyPair = await referenceImplementation.newKeyPair();
      final alicePublicKey = await aliceKeyPair.extractPublicKey();
      final bobKeyPair = await referenceImplementation.newKeyPair();
      final bobPublicKey = await bobKeyPair.extractPublicKey();

      // Compute secret using the platform implementation
      final aliceSecret = await (await keyExchangeAlgorithm.sharedSecretKey(
        keyPair: aliceKeyPair,
        remotePublicKey: bobPublicKey,
      ))
          .extractBytes();

      final bobSecret = await (await keyExchangeAlgorithm.sharedSecretKey(
        keyPair: bobKeyPair,
        remotePublicKey: alicePublicKey,
      ))
          .extractBytes();

      if (keyExchangeAlgorithm is X25519) {
        expect(aliceSecret, hasLength(32));
        expect(bobSecret, hasLength(32));
      }

      expect(
        aliceSecret,
        bobSecret,
        reason: 'Secrets are different',
      );
    });

    otherTests?.call();
  });
}
