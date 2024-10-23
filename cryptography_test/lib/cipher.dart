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
/// See [testCipher].
library cryptography_plus_test.cipher;

import 'dart:typed_data';

import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:test/expect.dart';
import 'package:test/scaffolding.dart';
import 'package:typed_data/typed_buffers.dart';

import 'hex.dart';

Cipher? _cipher;

/// Currently tested cipher.
Cipher get cipher => _cipher!;

/// Tests a cipher algorithm.
///
/// ## Example
/// ```dart
/// import 'package:cryptography_test/cipher.dart';
///
/// void main() {
///   testCipher(
///     builder: () => MyAlgorithm(),
///     otherTests: () {
///       test('something', () {
///         // ...
///       });
///     },
///   );
/// }
/// ```
void testCipher<T extends Cipher>({
  required T Function() builder,
  int? secretKeyLength,
  int? nonceLength,
  bool toSync = true,
  void Function(T a, T b)? onEquality,
  void Function(T cipher)? otherTests,
}) {
  final platformCipher = builder();

  group('$platformCipher:', () {
    _cipher = platformCipher;
    setUpAll(() {
      _cipher = platformCipher;
    });
    tearDownAll(() {
      _cipher = null;
    });

    secretKeyLength ??= cipher.toSync().secretKeyLength;
    nonceLength ??= cipher.toSync().nonceLength;

    test('secretKeyLength == $secretKeyLength', () {
      expect(cipher.secretKeyLength, secretKeyLength!);
    });

    test('nonceLength == $nonceLength', () {
      expect(cipher.nonceLength, nonceLength!);
    });

    test('no custom random', () {
      expect(
        // ignore: invalid_use_of_protected_member
        cipher.random,
        isNull,
      );
    });

    if (toSync) {
      test('cipher.toSync() returns a cipher with equal properties', () {
        final syncCipher = cipher.toSync();
        expect(syncCipher.secretKeyLength, cipher.secretKeyLength);
        expect(syncCipher.nonceLength, cipher.nonceLength);
        expect(syncCipher.macAlgorithm, cipher.macAlgorithm);
        if (onEquality != null) {
          onEquality(syncCipher as T, cipher as T);
        }
        expect(syncCipher, cipher);
        expect(syncCipher.hashCode, cipher.hashCode);
      });
    } else {
      test('cipher.toSync() throws $UnsupportedError', () {
        expect(
          () => cipher.toSync(),
          throwsUnsupportedError,
        );
      });
    }

    if (cipher.macAlgorithm != MacAlgorithm.empty) {
      group('decryption fails with bad MACs', () {
        test('cipher.decrypt()', () async {
          final clearText = Uint8List.fromList([1, 2, 3]);
          final secretKey = await cipher.newSecretKey();
          final secretBox = await cipher.encrypt(
            clearText,
            secretKey: secretKey,
          );

          // Correct MAC works
          await cipher.decrypt(
            secretBox,
            secretKey: secretKey,
          );

          // Bad MAC doesn't
          final badMac = Mac(secretBox.mac.bytes.map((e) => 0xFF ^ e).toList());
          final badSecretBox = SecretBox(
            secretBox.cipherText,
            nonce: secretBox.nonce,
            mac: badMac,
          );
          await expectLater(
            () => cipher.decrypt(
              badSecretBox,
              secretKey: secretKey,
            ),
            throwsA(
              isA<SecretBoxAuthenticationError>(),
            ),
          );
        });

        test('cipher.decryptString()', () async {
          final secretKey = await cipher.newSecretKey();
          final secretBox = await cipher.encryptString(
            'abc',
            secretKey: secretKey,
          );

          // Correct MAC works
          await cipher.decryptString(
            secretBox,
            secretKey: secretKey,
          );

          // Bad MAC doesn't
          final badMac = Mac(secretBox.mac.bytes.map((e) => 0xFF ^ e).toList());
          final badSecretBox = SecretBox(
            secretBox.cipherText,
            nonce: secretBox.nonce,
            mac: badMac,
          );
          await expectLater(
            () => cipher.decryptString(
              badSecretBox,
              secretKey: secretKey,
            ),
            throwsA(
              isA<SecretBoxAuthenticationError>(),
            ),
          );
        });

        test('cipher.decryptStream()', () async {
          final clearText = Uint8List.fromList([1, 2, 3]);
          final secretKey = await cipher.newSecretKey();
          final secretBox = await cipher.encrypt(
            clearText,
            secretKey: secretKey,
          );

          // Correct MAC works
          {
            final stream = cipher.decryptStream(
              Stream.fromIterable([secretBox.cipherText]),
              secretKey: secretKey,
              nonce: secretBox.nonce,
              mac: secretBox.mac,
            );
            await stream.toList();
          }

          // Bad MAC doesn't
          final badMac = Mac(secretBox.mac.bytes.map((e) => 0xFF ^ e).toList());
          final stream = cipher.decryptStream(
            Stream<List<int>>.fromIterable([secretBox.cipherText]),
            secretKey: secretKey,
            nonce: secretBox.nonce,
            mac: badMac,
          );
          try {
            final buffer = Uint8Buffer();
            await for (var chunk in stream) {
              buffer.addAll(chunk);
            }
            expect(buffer, clearText);
            fail('Should have thrown');
          } on SecretBoxAuthenticationError {
            // Ignore
          }
        });
      });
    }

    _testCipherWithChunks();

    if (otherTests != null) {
      otherTests(platformCipher);
    }
  });
}

void testCipherExample({
  required String summary,
  required List<int> clearText,
  required List<int> secretKey,
  required List<int> nonce,
  List<int> aad = const [],
  required List<int> cipherText,
  required List<int> mac,
}) {
  group(summary, () {
    test('encrypt and decrypt', () async {
      final secretBox = await cipher.encrypt(
        clearText,
        secretKey: SecretKeyData(secretKey),
        nonce: nonce,
        aad: aad,
      );
      expect(secretBox.cipherText, cipherText);
      expect(secretBox.mac, mac);

      final decrypted = await cipher.decrypt(
        secretBox,
        secretKey: SecretKeyData(secretKey),
        aad: aad,
      );
      expect(decrypted, clearText);
    });

    _testCipherWithChunks(
      input: clearText,
    );
  });
}

void _testCipherWithChunks({
  List<int>? input,
  List<int> aad = const [],
}) {
  if (input == null) {
    input = Uint8List(130);
    for (var i = 0; i < input.length; i++) {
      input[i] = i;
    }
  }
  final data = Uint8List.fromList(input);
  final dataCopy = Uint8List.fromList(data);
  setUp(() {
    for (var i = 0; i < data.length; i++) {
      data[i] = i % 256;
      dataCopy[i] = i % 256;
    }
  });

  final secretKey = SecretKeyData(
    Uint8List(cipher.secretKeyLength),
  );
  final nonce = Uint8List(cipher.nonceLength);

  test('encrypt()', () async {
    for (var n = 0; n <= 200; n++) {
      if (n > data.length) {
        return;
      }

      final clearText = Uint8List.view(data.buffer, 0, n);
      final clearTextCopy = Uint8List.view(dataCopy.buffer, 0, n);

      printOnFailure('clear text ($n bytes):\n${hexFromBytes(clearText)}');

      //
      // Use cipher.encrypt(...)
      //
      final firstSecretBox = await cipher.encrypt(
        clearText,
        secretKey: secretKey,
        nonce: nonce,
        aad: aad,
      );

      // Check that clear text bytes were not mutated.
      expect(clearText, clearTextCopy);

      // Use cipher.encrypt() again
      {
        final buffer = Uint8List(firstSecretBox.cipherText.length);
        final secretBoxAgain = await cipher.encrypt(
          clearText,
          secretKey: secretKey,
          nonce: nonce,
          aad: aad,
          possibleBuffer: buffer, // This time with buffer
        );

        // Check that clear text bytes were not mutated.
        expect(clearText, clearTextCopy);

        // Is nonce correct?
        expect(secretBoxAgain.nonce, firstSecretBox.nonce);

        // Is cipher text correct?
        expect(secretBoxAgain.cipherText, firstSecretBox.cipherText);
      }
    }
  });

  test('newState(): add all bytes at once', () async {
    for (var n = 0; n <= 200; n++) {
      if (n > data.length) {
        return;
      }

      final clearText = Uint8List.view(data.buffer, 0, n);
      final clearTextCopy = Uint8List.view(dataCopy.buffer, 0, n);

      printOnFailure('clear text ($n bytes):\n${hexFromBytes(clearText)}');

      final expectedSecretBox = await cipher.encrypt(
        clearText,
        secretKey: secretKey,
        nonce: nonce,
        aad: aad,
      );

      // Use cipher.newState()
      final state = cipher.newState();
      {
        await state.initialize(
          isEncrypting: true,
          secretKey: secretKey,
          nonce: nonce,
          aad: aad,
        );
        final cipherTextAgain = await state.convert(
          clearText,
          expectedMac: null,
        );

        // Check that clear text bytes were not mutated.
        expect(clearText, clearTextCopy);

        // Is cipher text correct?
        expect(
          hexFromBytes(cipherTextAgain),
          hexFromBytes(expectedSecretBox.cipherText),
        );

        // Is MAC correct?
        expect(
          hexFromBytes(state.mac.bytes),
          hexFromBytes(expectedSecretBox.mac.bytes),
        );
      }

      // Reinitialize the state and encrypt again.
      //
      // This time we do:
      //   convertChunkSync() // all the bytes
      //   convert() // empty
      {
        final cipherTextAgain = Uint8Buffer();
        await state.initialize(
          isEncrypting: true,
          secretKey: secretKey,
          nonce: nonce,
          aad: aad,
        );
        cipherTextAgain.addAll(
          state.convertChunkSync(clearText),
        );
        cipherTextAgain.addAll(
          await state.convert(
            const [],
            expectedMac: null,
          ),
        );

        // Check that clear text bytes were not mutated.
        expect(clearText, clearTextCopy);

        // Is cipher text correct?
        expect(
          hexFromBytes(cipherTextAgain),
          hexFromBytes(expectedSecretBox.cipherText),
        );

        // Is MAC correct?
        expect(
          hexFromBytes(state.mac.bytes),
          hexFromBytes(expectedSecretBox.mac.bytes),
        );
      }
    }
  });

  test('newState(): add 0 bytes, add remaining bytes', () async {
    // 64 bytes is the minimum for this test.
    for (var n = 0; n <= 200; n++) {
      if (n > data.length) {
        return;
      }

      final clearText = Uint8List.view(data.buffer, 0, n);
      final clearTextCopy = Uint8List.view(dataCopy.buffer, 0, n);

      printOnFailure('clear text ($n bytes):\n${hexFromBytes(clearText)}');

      //
      // Use cipher.encrypt(...)
      //
      final firstSecretBox = await cipher.encrypt(
        clearText,
        secretKey: secretKey,
        nonce: nonce,
        aad: aad,
      );

      // Check that clear text bytes were not mutated.
      expect(clearText, clearTextCopy);

      // Initialize a state and encrypt again.
      //
      // This time we do:
      //   convertChunkSync() // 64 bytes
      //   convert() // the rest
      final state = cipher.newState();
      final cipherText = Uint8Buffer();

      await state.initialize(
        isEncrypting: true,
        secretKey: secretKey,
        nonce: nonce,
        aad: aad,
      );
      cipherText.addAll(
        state.convertChunkSync(
          Uint8List.view(clearText.buffer, 0, 0),
        ),
      );
      cipherText.addAll(await state.convert(
        clearText,
        expectedMac: null,
      ));

      // Check that clear text bytes were not mutated.
      expect(clearText, clearTextCopy);

      // Is cipher text correct?
      expect(
        hexFromBytes(cipherText),
        hexFromBytes(firstSecretBox.cipherText),
      );

      // Is MAC correct?
      expect(
        hexFromBytes(state.mac.bytes),
        hexFromBytes(firstSecretBox.mac.bytes),
      );
    }
  });

  test('newState(): add 1 byte, add remaining bytes', () async {
    // 64 bytes is the minimum for this test.
    for (var n = 1; n <= 200; n++) {
      if (n > data.length) {
        return;
      }

      final clearText = Uint8List.view(data.buffer, 0, n);
      final clearTextCopy = Uint8List.view(dataCopy.buffer, 0, n);

      printOnFailure('clear text ($n bytes):\n${hexFromBytes(clearText)}');

      //
      // Use cipher.encrypt(...)
      //
      final firstSecretBox = await cipher.encrypt(
        clearText,
        secretKey: secretKey,
        nonce: nonce,
        aad: aad,
      );

      // Check that clear text bytes were not mutated.
      expect(clearText, clearTextCopy);

      // Initialize a state and encrypt again.
      //
      // This time we do:
      //   convertChunkSync() // 64 bytes
      //   convert() // the rest
      final state = cipher.newState();
      final cipherText = Uint8Buffer();

      await state.initialize(
        isEncrypting: true,
        secretKey: secretKey,
        nonce: nonce,
        aad: aad,
      );
      cipherText.addAll(
        state.convertChunkSync(
          Uint8List.view(clearText.buffer, 0, 1),
        ),
      );
      cipherText.addAll(
        await state.convert(
          Uint8List.view(clearText.buffer, 1, clearText.length - 1),
          expectedMac: null,
        ),
      );

      // Check that clear text bytes were not mutated.
      expect(clearText, clearTextCopy);

      // Is cipher text correct?
      expect(
        hexFromBytes(cipherText),
        hexFromBytes(firstSecretBox.cipherText),
      );

      // Is MAC correct?
      expect(
        hexFromBytes(state.mac.bytes),
        hexFromBytes(firstSecretBox.mac.bytes),
      );
    }
  });

  test('newState(): add 64 bytes, add remaining bytes', () async {
    // 64 bytes is the minimum for this test.
    for (var n = 64; n <= 200; n++) {
      if (n > data.length) {
        return;
      }

      final clearText = Uint8List.view(data.buffer, 0, n);
      final clearTextCopy = Uint8List.view(dataCopy.buffer, 0, n);

      printOnFailure('clear text ($n bytes):\n${hexFromBytes(clearText)}');

      //
      // Use cipher.encrypt(...)
      //
      final firstSecretBox = await cipher.encrypt(
        clearText,
        secretKey: secretKey,
        nonce: nonce,
        aad: aad,
      );

      // Check that clear text bytes were not mutated.
      expect(clearText, clearTextCopy);

      // Initialize a state and encrypt again.
      //
      // This time we do:
      //   convertChunkSync() // 64 bytes
      //   convert() // the rest
      final state = cipher.newState();
      final cipherText = Uint8Buffer();

      await state.initialize(
        isEncrypting: true,
        secretKey: secretKey,
        nonce: nonce,
        aad: aad,
      );
      cipherText.addAll(
        state.convertChunkSync(
          Uint8List.view(clearText.buffer, 0, 64),
        ),
      );
      cipherText.addAll(await state.convert(
        Uint8List.view(clearText.buffer, 64, clearText.length - 64),
        expectedMac: null,
      ));

      // Check that clear text bytes were not mutated.
      expect(clearText, clearTextCopy);

      // Is cipher text correct?
      expect(
        hexFromBytes(cipherText),
        hexFromBytes(firstSecretBox.cipherText),
      );

      // Is MAC correct?
      expect(
        hexFromBytes(state.mac.bytes),
        hexFromBytes(firstSecretBox.mac.bytes),
      );
    }
  });

  test('add 1 byte, add 2 bytes, add remaining bytes', () async {
    // 3 is minimum size for this test.
    for (var n = 3; n <= 200; n++) {
      if (n > data.length) {
        return;
      }

      final clearText = Uint8List.view(data.buffer, 0, n);
      final clearTextCopy = Uint8List.view(dataCopy.buffer, 0, n);

      printOnFailure('clear text ($n bytes):\n${hexFromBytes(clearText)}');

      //
      // Use cipher.encrypt(...)
      //
      final firstSecretBox = await cipher.encrypt(
        clearText,
        secretKey: secretKey,
        nonce: nonce,
        aad: aad,
      );

      // Check that clear text bytes were not mutated.
      expect(clearText, clearTextCopy);

      // Initialize a state and encrypt again.
      //
      // This time we do:
      //   convertChunkSync() // 1 byte
      //   convertChunkSync() // 2 bytes
      //   convert() // the rest
      final state = cipher.newState();
      final cipherText = Uint8Buffer();
      await state.initialize(
        isEncrypting: true,
        secretKey: secretKey,
        nonce: nonce,
      );

      // 1 byte
      cipherText.addAll(
        state.convertChunkSync(
          Uint8List.view(clearText.buffer, 0, 1),
        ),
      );

      // 2 bytes
      cipherText.addAll(
        state.convertChunkSync(
          Uint8List.view(clearText.buffer, 1, 2),
        ),
      );

      // The other bytes
      cipherText.addAll(
        await state.convert(
          Uint8List.view(clearText.buffer, 3, clearText.length - 3),
          expectedMac: null,
        ),
      );

      // Check that clear text bytes were not mutated.
      expect(clearText, clearTextCopy);

      // Is cipher text correct?
      expect(
        hexFromBytes(cipherText),
        hexFromBytes(firstSecretBox.cipherText),
      );

      // Is MAC correct?
      expect(
        hexFromBytes(state.mac.bytes),
        hexFromBytes(firstSecretBox.mac.bytes),
      );
    }
  });
}
