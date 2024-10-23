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

/// Test utilities for [SignatureAlgorithm] classes.
///
/// ## Example
/// See [testSignatureAlgorithm].
library cryptography_plus_test.signature_algorithm;

import 'dart:typed_data';

import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:cryptography_plus/dart.dart';
import 'package:test/expect.dart';
import 'package:test/scaffolding.dart';

SignatureAlgorithm? _signatureAlgorithm;

/// Currently tested [SignatureAlgorithm].
SignatureAlgorithm get signatureAlgorithm => _signatureAlgorithm!;

/// Tests a [SignatureAlgorithm].
///
/// ## Example
/// ```dart
/// import 'package:cryptography_test/signature.dart';
///
/// void main() {
///   testSignatureAlgorithm(
///     builder: () => MyAlgorithm(),
///     otherTests: () {
///       test('something', () {
///         // ...
///       });
///     },
///   );
/// }
/// ```
void testSignatureAlgorithm({
  required SignatureAlgorithm Function() builder,
  bool Function()? skip,
  required void Function()? otherTests,
  DartSignatureAlgorithmMixin? dartImplementation,
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
      _signatureAlgorithm = builder();
    });
    tearDown(() {
      _signatureAlgorithm = null;
    });

    test('newKeyPair(...) returns unique, valid key pairs', () async {
      final keyPair0 = await signatureAlgorithm.newKeyPair();
      final keyPair1 = await signatureAlgorithm.newKeyPair();
      if (keyPair0 is SimpleKeyPairData && keyPair1 is SimpleKeyPairData) {
        expect(keyPair0.bytes, hasLength(32));
        expect(keyPair1.bytes, hasLength(32));
        expect(keyPair0.bytes, isNot(keyPair1.bytes));
      }

      final publicKey0 = await keyPair0.extractPublicKey();
      final publicKey1 = await keyPair1.extractPublicKey();
      if (publicKey0 is SimplePublicKey && publicKey1 is SimplePublicKey) {
        expect(publicKey0.bytes, hasLength(32));
        expect(publicKey1.bytes, hasLength(32));
        expect(publicKey0.bytes, isNot(publicKey1.bytes));
      }

      final referenceImplementation = dartImplementation ?? signatureAlgorithm;
      final signature0 = await referenceImplementation.sign(
        [1, 2, 3],
        keyPair: keyPair0,
      );
      expect(
        await referenceImplementation.verify(
          [1, 2, 3],
          signature: signature0,
        ),
        isTrue,
      );
      expect(
        await referenceImplementation.verify(
          [0, 0, 0],
          signature: signature0,
        ),
        isFalse,
      );
    });

    test('sign(...)', () async {
      final referenceImplementation = dartImplementation ?? signatureAlgorithm;
      final keyPair = await referenceImplementation.newKeyPair();
      final expectedPublicKey = await keyPair.extractPublicKey();
      final data = Uint8List.fromList('Hello, world!'.codeUnits);

      final signature = await signatureAlgorithm.sign(data, keyPair: keyPair);
      if (signatureAlgorithm is Ed25519) {
        expect(
          signature.bytes,
          hasLength(64),
          reason: 'Signature should have the correct length.',
        );
      }
      expect(
        signature.publicKey,
        expectedPublicKey,
        reason: 'Signature should have the same public key.',
      );

      // Test using the pure Dart implementation.
      expect(
        await referenceImplementation.verify(
          data,
          signature: signature,
        ),
        isTrue,
      );
      expect(
        await referenceImplementation.verify(
          List<int>.filled(data.length, 0),
          signature: signature,
        ),
        isFalse,
      );
    });

    test('verify(...) when signature is valid', () async {
      final referenceImplementation = dartImplementation ?? signatureAlgorithm;
      final keyPair = await referenceImplementation.newKeyPair();
      final data = Uint8List.fromList('Hello, world!'.codeUnits);
      final signature = await referenceImplementation.sign(
        data,
        keyPair: keyPair,
      );

      final isOk = await signatureAlgorithm.verify(
        data,
        signature: signature,
      );
      expect(isOk, isTrue);
    });

    test('verify(...) when signature is invalid', () async {
      final referenceImplementation = dartImplementation ?? signatureAlgorithm;
      final keyPair = await referenceImplementation.newKeyPair();
      final data = Uint8List.fromList('Hello, world!'.codeUnits);
      final signature = await referenceImplementation.sign(
        data,
        keyPair: keyPair,
      );

      final otherData = Uint8List.fromList('HELLO, WORLD!'.codeUnits);
      final isOk = await signatureAlgorithm.verify(
        otherData,
        signature: signature,
      );
      expect(isOk, isFalse);
    });

    otherTests?.call();
  });
}
