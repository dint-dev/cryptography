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

import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:cryptography_plus/dart.dart';
import 'package:cryptography_flutter_plus/cryptography_flutter_plus.dart';
import 'package:flutter_test/flutter_test.dart';

import '_helpers.dart';

class _BackgroundCryptography extends FlutterCryptography {
  @override
  AesGcm aesGcm({
    int secretKeyLength = 32,
    int nonceLength = AesGcm.defaultNonceLength,
  }) {
    return BackgroundAesGcm(
      secretKeyLength: secretKeyLength,
      nonceLength: nonceLength,
    );
  }

  @override
  Chacha20 chacha20Poly1305Aead() {
    return BackgroundChacha.poly1305Aead();
  }
}

void testCiphers() {
  group('$FlutterCryptography:', () {
    _testCiphers();
  });

  group('$_BackgroundCryptography:', () {
    // Using setUp() is not enough because we want correct test descriptions.
    final oldCryptography = Cryptography.instance;
    Cryptography.instance = _BackgroundCryptography();

    setUp(() {
      Cryptography.instance = _BackgroundCryptography();
    });

    _testCiphers();

    Cryptography.instance = oldCryptography;
  });
}

void _testCiphers() {
  // AES-GCM
  {
    const maxRelativeLatency = 2.0;

    _testCipher(
      defaultCipherFactory: () => AesGcm.with128bits(),
      platformCipherFactory: () => FlutterAesGcm.with128bits(),
      dartFactory: () => DartAesGcm.with128bits(),
      maxRelativeLatency: maxRelativeLatency,
    );
    _testCipher(
      defaultCipherFactory: () => AesGcm.with192bits(),
      platformCipherFactory: () => FlutterAesGcm.with192bits(),
      dartFactory: () => DartAesGcm.with192bits(),
      maxRelativeLatency: maxRelativeLatency,
    );
    _testCipher(
      defaultCipherFactory: () => AesGcm.with256bits(),
      platformCipherFactory: () => FlutterAesGcm.with256bits(),
      dartFactory: () => DartAesGcm.with256bits(),
      maxRelativeLatency: maxRelativeLatency,
    );
  }

  // CHACHA20_POLY1305_AEAD
  {
    const maxRelativeLatency = 2.0;

    _testCipher(
      defaultCipherFactory: () => Chacha20.poly1305Aead(),
      platformCipherFactory: () => FlutterChacha20.poly1305Aead(),
      dartFactory: () => const DartChacha20.poly1305Aead(),
      maxRelativeLatency: maxRelativeLatency,
    );
  }
}

List<_CipherExample> _cipherExamples(Cipher cipher) {
  final secretKey0 = SecretKey(
    List<int>.filled(cipher.secretKeyLength, 1),
  );
  final secretKey1 = SecretKey(
    List<int>.filled(cipher.secretKeyLength, 2),
  );
  final nonce0 = cipher.newNonce();
  final nonce1 = cipher.newNonce();
  const empty = <int>[];
  const aad1 = <int>[1, 2, 3];

  const lengths = [
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    15,
    16,
    17,
    31,
    32,
    33,
    63,
    64,
    65,
    4095,
    4096,
    4097
  ];

  return <_CipherExample>[
    //
    // Different clearText
    //
    ...lengths.map((length) {
      final clearText = List<int>.generate(length, (i) => 0xFF & i);
      return _CipherExample(
        summary: 'clearText length $length',
        clearText: clearText,
        secretKey: secretKey0,
        nonce: nonce0,
        aad: empty,
      );
    }),

    //
    // Different secretKey
    //
    _CipherExample(
      summary: 'clearText0, secretKey1',
      clearText: [1, 2, 3],
      secretKey: secretKey1,
      nonce: nonce0,
      aad: empty,
    ),

    //
    // Different nonce
    //
    _CipherExample(
      summary: 'clearText0, nonce1',
      clearText: [1, 2, 3],
      secretKey: secretKey0,
      nonce: nonce1, // <-- DIFFERENCE
      aad: empty,
    ),

    //
    // Different AAD
    //
    if (cipher.macAlgorithm.supportsAad)
      _CipherExample(
        summary: 'clearText0, aad1',
        clearText: [1, 2, 3],
        secretKey: secretKey0,
        nonce: nonce0,
        aad: aad1, // <-- DIFFERENCE
      ),
  ];
}

void _testCipher({
  required Cipher Function() defaultCipherFactory,
  required Cipher Function() platformCipherFactory,
  required Cipher Function() dartFactory,
  double maxRelativeLatency = 2.0,
}) {
  var cipher = platformCipherFactory();
  final dartCipher = dartFactory();
  final defaultCipher = defaultCipherFactory();

  setUp(() {
    cipher = platformCipherFactory();
  });

  group('$defaultCipher:', () {
    test(
        'Default cipher in this platform implements $FlutterCipher or $BackgroundCipher',
        () {
      expect(
        defaultCipher,
        anyOf(
          isA<FlutterCipher>(),
          isA<BackgroundCipher>(),
        ),
      );
    });
    //
    // Define example inputs.
    //
    final examples = _cipherExamples(cipher);

    //
    // Define secret boxes generated by the fallback implementation.
    //
    setUpAll(() async {
      for (var i = 0; i < examples.length; i++) {
        final example = examples[i];
        final secretBox = await dartCipher.encrypt(
          example.clearText,
          secretKey: example.secretKey,
          nonce: example.nonce,
          aad: example.aad,
        );
        expect(secretBox.nonce, example.nonce);

        final previousExamples = examples.sublist(0, i);
        for (var previous in previousExamples) {
          if (previous.dartSecretBox == secretBox) {
            fail(
              'Duplicate secret boxes:\n'
              '  ${previous.summary}\n'
              '  ${example.summary}',
            );
          }
        }

        example.dartSecretBox = secretBox;
      }
    });

    //
    // Test cases.
    //
    test('nonceLength', () {
      expect(
        cipher.nonceLength,
        dartCipher.nonceLength,
      );
    });

    test('macAlgorithm.macLength', () {
      expect(
        cipher.macAlgorithm.macLength,
        dartCipher.macAlgorithm.macLength,
      );
    });

    test('macAlgorithm.supportsAad', () {
      expect(
        cipher.macAlgorithm.supportsAad,
        dartCipher.macAlgorithm.supportsAad,
      );
    });

    // Minimum lengths
    final lengths = {
      100,
      1 * 1000 * 1000,
      10 * 1000 * 1000,
      50 * 1000 * 1000,
      BackgroundCipher.defaultChannelPolicy.minLength,
      FlutterCipher.defaultChannelPolicy.minLength,
    }.toList()
      ..sort();

    for (var length in lengths) {
      _testCipherPerformance(
        cipher: defaultCipher,
        dartCipher: dartCipher,
        maxRelativeLatency: 3.0,
        size: length,
        n: max(1, 1000000 ~/ length),
      );
    }

    //
    // Test all the examples.
    //
    for (var example in examples) {
      _testExample(
        cipher: cipher,
        dartCipher: dartCipher,
        example: example,
      );
    }
  });
}

/// Converts a list of bytes to a hexadecimal string.
String hexFromBytes(Iterable<int> iterable) {
  final list = iterable.toList();
  final sb = StringBuffer();
  for (var i = 0; i < list.length; i++) {
    if (i > 0) {
      if (i % 16 == 0) {
        sb.write('\n');
      } else {
        sb.write(' ');
      }
    }
    sb.write(list[i].toRadixString(16).padLeft(2, '0'));
  }
  return sb.toString();
}

void _testExample({
  required Cipher cipher,
  required Cipher dartCipher,
  required _CipherExample example,
}) {
  group('${example.summary}:', () {
    test('encrypt(...)', () async {
      final dartSecretBox = example.dartSecretBox!;

      final secretBox = await cipher.encrypt(
        example.clearText,
        secretKey: example.secretKey,
        nonce: example.nonce,
        aad: example.aad,
      );

      // Nonce
      expect(
        hexFromBytes(secretBox.nonce),
        hexFromBytes(dartSecretBox.nonce),
        reason: '$cipher nonce != ${dartCipher.runtimeType} nonce',
      );

      // Cipher text
      expect(
        hexFromBytes(secretBox.cipherText),
        hexFromBytes(dartSecretBox.cipherText),
        reason:
            '$cipher cipherText (length: ${secretBox.cipherText.length}) != ${dartCipher.runtimeType} cipherText (length ${dartSecretBox.cipherText.length})',
      );

      // MAC
      expect(
        hexFromBytes(secretBox.mac.bytes),
        hexFromBytes(dartSecretBox.mac.bytes),
        reason: '$cipher MAC != ${dartCipher.runtimeType} MAC',
      );

      expect(secretBox.cipherText, isA<Uint8List>());
    });

    test('encrypt(...): fails when secret key has wrong size ', () async {
      final incorrectSecretKey = SecretKey([
        ...(await example.secretKey.extractBytes()),
        1,
      ]);
      await expectLater(
        () => cipher.encrypt(
          example.clearText,
          secretKey: incorrectSecretKey,
          nonce: example.nonce,
          aad: example.aad,
        ),
        throwsArgumentError,
      );
    });

    test('decrypt(...)', () async {
      final secretBox = example.dartSecretBox!;

      final clearText = await cipher.decrypt(
        secretBox,
        secretKey: example.secretKey,
        aad: example.aad,
      );
      expect(clearText, isA<Uint8List>());
      expect(
        hexFromBytes(clearText),
        hexFromBytes(example.clearText),
        reason:
            '$cipher clearText (length ${clearText.length}) != example clear text (length ${example.clearText.length})',
      );
    });

    test('decrypt(...): fails when MAC has wrong size', () async {
      final secretBox = example.dartSecretBox!;
      final incorrectMac = Mac([...secretBox.mac.bytes, 0]);
      final incorrectSecretBox = SecretBox(
        secretBox.cipherText,
        nonce: secretBox.nonce,
        mac: incorrectMac,
      );
      await expectLater(
        () => cipher.decrypt(
          incorrectSecretBox,
          secretKey: example.secretKey,
          aad: example.aad,
        ),
        throwsA(isA<SecretBoxAuthenticationError>()),
      );
    });

    test('decrypt(...): fails when MAC is incorrect', () async {
      final secretBox = example.dartSecretBox!;
      final incorrectMac = Mac(
        secretBox.mac.bytes.map((e) => 0xFF & (e + 1)).toList(),
      );
      final incorrectSecretBox = SecretBox(
        secretBox.cipherText,
        nonce: secretBox.nonce,
        mac: incorrectMac,
      );

      if (cipher.macAlgorithm == MacAlgorithm.empty) {
        // Special case: no MAC.
        // In this case, decrypting should succeed.
        await cipher.decrypt(
          incorrectSecretBox,
          secretKey: example.secretKey,
          aad: example.aad,
        );
      } else {
        // Decrypt when the MAC is incorrect.
        expect(
          () => cipher.decrypt(
            incorrectSecretBox,
            secretKey: example.secretKey,
            aad: example.aad,
          ),
          throwsA(isA<SecretBoxAuthenticationError>()),
        );
      }
    });

    test('decrypt(...): fails when secret key is incorrect', () async {
      final secretBox = example.dartSecretBox!;
      final incorrectSecretKey = await cipher.newSecretKey();

      // Special case: no MAC.
      // In this case, decrypting should succeed unless invalid padding is
      // detected.
      if (cipher.macAlgorithm == MacAlgorithm.empty) {
        try {
          await cipher.decrypt(
            secretBox,
            secretKey: incorrectSecretKey,
            aad: example.aad,
          );
        } on SecretBoxPaddingError {
          // OK
        }
        return;
      }

      try {
        //
        // Decrypt with incorrect secret key.
        //
        await cipher.decrypt(
          secretBox,
          secretKey: incorrectSecretKey,
          aad: example.aad,
        );
        // Decrypting should have failed.
        fail(
          'Expected $SecretBoxAuthenticationError'
          ' or $SecretBoxPaddingError',
        );
      } on SecretBoxAuthenticationError {
        // OK.
      }
    });

    test('decrypt(...): fails when nonce is incorrect', () async {
      final secretBox = example.dartSecretBox!;
      final incorrectNonce = cipher.newNonce();
      expect(incorrectNonce, isNot(example.nonce));
      final incorrectSecretBox = SecretBox(
        secretBox.cipherText,
        nonce: incorrectNonce,
        mac: secretBox.mac,
      );

      // Special case: no MAC.
      // In this case, decrypting should succeed unless invalid padding is
      // detected.
      if (cipher.macAlgorithm == MacAlgorithm.empty) {
        try {
          await cipher.decrypt(
            secretBox,
            secretKey: example.secretKey,
            aad: example.aad,
          );
        } on SecretBoxPaddingError {
          // OK
        }
        return;
      }

      try {
        //
        // Decrypt with incorrect nonce.
        //
        final clearText = await cipher.decrypt(
          incorrectSecretBox,
          secretKey: example.secretKey,
          aad: example.aad,
        );

        // Decrypting should have failed except in special cases.
        //
        // Special case: HMAC, which does not use nonce.
        if (cipher.macAlgorithm is Hmac) {
          if (example.clearText.isNotEmpty && example.clearText.length >= 8) {
            expect(clearText, isNot(example.clearText));
          }
          return;
        }
        fail(
          'Expected $SecretBoxAuthenticationError'
          ' or $SecretBoxPaddingError',
        );
      } on SecretBoxAuthenticationError {
        // OK
      } on SecretBoxPaddingError {
        // OK
      }
    });
  });
}

class _CipherExample {
  final String summary;
  final List<int> clearText;
  final SecretKey secretKey;
  final List<int> nonce;
  final List<int> aad;
  SecretBox? dartSecretBox;

  _CipherExample({
    required this.summary,
    required this.clearText,
    required this.secretKey,
    required this.nonce,
    required this.aad,
  });
}

void _testCipherPerformance({
  required Cipher cipher,
  required Cipher dartCipher,
  required double maxRelativeLatency,
  required int size,
  required int n,
}) {
  test('size=${sizeString(size)} and n=${amountString(n)} performance',
      () async {
    printOnFailure('Implementation is: $cipher');
    if (cipher.runtimeType == dartCipher.runtimeType) {
      return;
    }
    final clearText = Uint8List(size);
    final secretKey = await cipher.newSecretKey();
    final nonce = cipher.newNonce();
    await cipher.encrypt(
      clearText,
      secretKey: secretKey,
      nonce: nonce,
    );
    await expectFasterThanPureDart(
      description:
          '$cipher when size=${sizeString(size)} and n=${amountString(n)}',
      dart: () async {
        await dartCipher.encrypt(
          clearText,
          secretKey: secretKey,
          nonce: nonce,
        );
      },
      dartObject: dartCipher,
      benchmarked: () async {
        await cipher.encrypt(
          clearText,
          secretKey: secretKey,
          nonce: nonce,
        );
      },
      benchmarkedObject: cipher,
      maxRelativeLatency: maxRelativeLatency,
      n: n,
    );
  }, timeout: const Timeout.factor(10.0));
}
