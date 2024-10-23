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

import 'dart:math';
import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:cryptography_plus/helpers.dart';
import 'package:test/test.dart';

import '../hex.dart';

void testHmac() {
  _testHmac(Hmac.sha256());
}

void _testHmac(Hmac hmac) {
  test('newSink(): empty key fails', () async {
    final secretKey = SecretKey(<int>[]);
    expect(await secretKey.extractBytes(), hasLength(0));
    final future = hmac.newMacSink(secretKey: secretKey);
    await expectLater(future, throwsArgumentError);
  });

  test('newSink(): closing twice is ok', () async {
    final secretKey = SecretKey(<int>[1, 2, 3]);
    final sink = await hmac.newMacSink(secretKey: secretKey);
    sink.close();
    sink.close();
  });

  test('newSink(): adding after closing fails', () async {
    final secretKey = SecretKey(<int>[1, 2, 3]);
    final sink = await hmac.newMacSink(secretKey: secretKey);
    sink.close();
    expect(() => sink.add([]), throwsStateError);
    expect(() => sink.addSlice([1], 0, 1, false), throwsStateError);
  });

  test('Hmac.sha256().calculateMac(...): different secretKey and data lengths',
      () async {
    final buffer = Uint8List(129);
    for (var i = 0; i < buffer.length; i++) {
      buffer[i] = i;
    }

    for (var n = 0; n < buffer.length; n++) {
      final data = buffer.buffer.asUint8List(0, n);
      final secretKey = SecretKeyData(data.buffer.asUint8List(max(1, n)));

      for (var i = 0; i < data.length; i++) {
        data[i] = 0xFF & i;
      }

      // ignore: unused_local_variable
      final mac = await Hmac.sha256().calculateMac(
        data,
        secretKey: secretKey,
        nonce: const <int>[],
      );

      // // Use 'package:crypto' for calculating the correct answer
      final secretKeyData = await secretKey.extract();
      final expectedBytes = crypto.Hmac(
        crypto.sha256,
        secretKeyData.bytes,
      ).convert(data).bytes;
      expect(
        hexFromBytes(mac.bytes),
        hexFromBytes(expectedBytes),
        reason: 'length: $n',
      );
    }
  });

  test('Hmac.sha512().calculateMac(...): different secretKey and data lengths',
      () async {
    final buffer = Uint8List(129);
    for (var i = 0; i < buffer.length; i++) {
      buffer[i] = i;
    }
    for (var n = 0; n < buffer.length; n++) {
      final data = buffer.buffer.asUint8List(0, n);
      final secretKey = SecretKeyData(data.buffer.asUint8List(max(1, n)));

      // ignore: unused_local_variable
      final mac = await Hmac.sha512().calculateMac(
        data,
        secretKey: secretKey,
        nonce: const <int>[],
      );

      // // Use 'package:crypto' for calculating the correct answer
      final expectedBytes = crypto.Hmac(
        crypto.sha512,
        secretKey.bytes,
      ).convert(data).bytes;
      expect(
        hexFromBytes(mac.bytes),
        hexFromBytes(expectedBytes),
        reason: 'length: $n',
      );
    }
  });

  test(
      'Hmac.sha512(), addSlice(), addSlice(): different secretKey and data lengths',
      () async {
    final buffer = Uint8List(129);
    for (var i = 0; i < buffer.length; i++) {
      buffer[i] = i;
    }
    for (var n = 0; n < buffer.length; n++) {
      final data = buffer.buffer.asUint8List(0, n);
      final secretKey = SecretKeyData(data.buffer.asUint8List(max(1, n)));
      for (var i = 0; i < data.length; i++) {
        data[i] = 0xFF & i;
      }

      // ignore: unused_local_variable
      final sink = await Hmac.sha512().newMacSink(
        secretKey: secretKey,
      );
      sink.addSlice(data, 0, data.length ~/ 2, false);
      sink.addSlice(data, data.length ~/ 2, data.length, true);
      final mac = await sink.mac();

      // // Use 'package:crypto' for calculating the correct answer
      final expectedBytes = crypto.Hmac(
        crypto.sha512,
        secretKey.bytes,
      ).convert(data).bytes;
      expect(
        hexFromBytes(mac.bytes),
        hexFromBytes(expectedBytes),
        reason: 'length: $n',
      );
    }
  });

  test(
      'Hmac.sha512(), add(), add(), close(): different secretKey and data lengths',
      () async {
    final buffer = Uint8List(129);
    for (var i = 0; i < buffer.length; i++) {
      buffer[i] = i;
    }
    for (var n = 0; n < buffer.length; n++) {
      final data = buffer.buffer.asUint8List(0, n);
      final secretKey = SecretKeyData(data.buffer.asUint8List(max(1, n)));
      for (var i = 0; i < data.length; i++) {
        data[i] = 0xFF & i;
      }

      // ignore: unused_local_variable
      final sink = await Hmac.sha512().newMacSink(
        secretKey: secretKey,
      );
      sink.add(data.sublist(0, data.length ~/ 2));
      sink.add(data.sublist(data.length ~/ 2, data.length));
      sink.close();
      final mac = await sink.mac();

      // // Use 'package:crypto' for calculating the correct answer
      final expectedBytes = crypto.Hmac(
        crypto.sha512,
        secretKey.bytes,
      ).convert(data).bytes;
      expect(
        hexFromBytes(mac.bytes),
        hexFromBytes(expectedBytes),
        reason: 'length: $n',
      );
    }
  });

  test('newSink(): different secretKey and data lengths', () async {
    for (var n = 2; n < 1024; n++) {
      final secretKey = SecretKey(Uint8List(n));
      final data = Uint8List(n);
      for (var i = 0; i < data.length; i++) {
        data[i] = 0xFF & i;
      }
      final sink = await hmac.newMacSink(
        secretKey: secretKey,
      );
      sink.addSlice(data, 0, 0, false);
      sink.addSlice(data, 0, 1, false);
      sink.add(data.sublist(1, 2));
      sink.addSlice(data, 2, data.length, true);
      sink.close();

      // ignore: unused_local_variable
      final mac = await sink.mac();

      // // Use 'package:crypto' for calculating the correct answer
      // final extracted = await secretKey.extract();
      // final expectedBytes =
      //     google_crypto.Hmac(google_crypto.sha256, extracted.bytes)
      //         .convert(data)
      //         .bytes;
      // expect(
      //   hexFromBytes(mac.bytes),
      //   hexFromBytes(expectedBytes),
      // );
    }
  }, timeout: Timeout.factor(4.0));

  group('RFC 4231:', () {
    group('test vector #1:', () {
      // "Hi There"
      final input = hexToBytes(
        '4869205468657265',
      );
      final secretKey = SecretKey(hexToBytes(
        '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'
        '0b0b0b0b',
      ));

      test('sha224, calculateMac()', () async {
        final expected = hexToBytes(
          '896fb1128abbdf196832107cd49df33f'
          '47b4b1169912ba4f53684b22',
        );
        final hmac = Hmac(Sha224());
        final hash = await hmac.calculateMac(
          input,
          secretKey: secretKey,
          nonce: const <int>[],
        );
        expect(
          hexFromBytes(hash.bytes),
          hexFromBytes(expected),
        );
        expect(
          await hmac.calculateMac(
            input,
            secretKey: secretKey,
            nonce: const <int>[],
          ),
          hash,
        );
      });

      test('sha256, calculateMac()', () async {
        final expected = hexToBytes(
          'b0344c61d8db38535ca8afceaf0bf12b'
          '881dc200c9833da726e9376c2e32cff7',
        );
        final hmac = Hmac(Sha256());
        final hash = await hmac.calculateMac(
          input,
          secretKey: secretKey,
          nonce: const <int>[],
        );
        expect(
          hexFromBytes(hash.bytes),
          hexFromBytes(expected),
        );
        expect(
          await hmac.calculateMac(
            input,
            secretKey: secretKey,
            nonce: const <int>[],
          ),
          hash,
        );
      });

      test('sha256, addSlice()', () async {
        final expected = hexToBytes(
          'b0344c61d8db38535ca8afceaf0bf12b'
          '881dc200c9833da726e9376c2e32cff7',
        );
        final hmac = Hmac(Sha256());
        final sink = await hmac.newMacSink(secretKey: secretKey);
        sink.addSlice(input, 0, input.length, true);
        final hash = await sink.mac();
        expect(
          hexFromBytes(hash.bytes),
          hexFromBytes(expected),
        );
        expect(
          await hmac.calculateMac(
            input,
            secretKey: secretKey,
            nonce: const <int>[],
          ),
          hash,
        );
      });

      test('sha256, add(), close()', () async {
        final expected = hexToBytes(
          'b0344c61d8db38535ca8afceaf0bf12b'
          '881dc200c9833da726e9376c2e32cff7',
        );
        final hmac = Hmac(Sha256());
        final sink = await hmac.newMacSink(secretKey: secretKey);
        sink.add(input);
        sink.close();
        final hash = await sink.mac();
        expect(
          hexFromBytes(hash.bytes),
          hexFromBytes(expected),
        );
        expect(
          await hmac.calculateMac(
            input,
            secretKey: secretKey,
            nonce: const <int>[],
          ),
          hash,
        );
      });

      test('sha384, calculateMac()', () async {
        final expected = hexToBytes(
          'afd03944d84895626b0825f4ab46907f'
          '15f9dadbe4101ec682aa034c7cebc59c'
          'faea9ea9076ede7f4af152e8b2fa9cb6',
        );
        final hmac = Hmac(Sha384());
        final hash = await hmac.calculateMac(
          input,
          secretKey: secretKey,
          nonce: const <int>[],
        );
        expect(
          hexFromBytes(hash.bytes),
          hexFromBytes(expected),
        );
      });

      test('sha512, calculateMac()', () async {
        final expected = hexToBytes(
          '87aa7cdea5ef619d4ff0b4241a1d6cb0'
          '2379f4e2ce4ec2787ad0b30545e17cde'
          'daa833b7d6b8a702038b274eaea3f4e4'
          'be9d914eeb61f1702e696c203a126854',
        );
        final hmac = Hmac(Sha512());
        final hash = await hmac.calculateMac(
          input,
          secretKey: secretKey,
          nonce: const <int>[],
        );
        expect(
          hexFromBytes(hash.bytes),
          hexFromBytes(expected),
        );
      });
    });

    test(
      'Hmac.sha256(): tests against package:crypto',
      () {
        final algorithm = Hmac.sha256().toSync();
        final secretKeyData = SecretKeyData([1, 2, 3]);
        final googleHmac = crypto.Hmac(crypto.sha256, secretKeyData.bytes);
        final random = SecureRandom.fast;
        final input = Uint8List(300);

        for (var i = 0; i < 1000; i++) {
          fillBytesWithSecureRandom(input, random: random);
          for (var j = 1; j < input.length; j++) {
            final slice = input.buffer.asUint8List(0, j);
            final hash = algorithm.calculateMacSync(
              slice,
              secretKeyData: secretKeyData,
              nonce: const [],
            ).bytes;
            final packageCryptoHash = googleHmac.convert(slice).bytes;
            // Use if statement for better performance
            if (!const ListEquality().equals(hash, packageCryptoHash)) {
              expect(
                hexFromBytes(hash),
                hexFromBytes(packageCryptoHash),
              );
            }

            {
              final sink = algorithm.newMacSinkSync(
                secretKeyData: secretKeyData,
              );
              sink.add(slice);
              sink.close();
              expect(
                sink.macSync().bytes,
                packageCryptoHash,
              );
            }

            {
              final sink = algorithm.newMacSinkSync(
                secretKeyData: secretKeyData,
              );
              final n = slice.length ~/ 2;
              sink.addSlice(slice, 0, n, false);
              sink.addSlice(slice, n, slice.length, true);
              expect(
                sink.macSync().bytes,
                packageCryptoHash,
              );
            }

            {
              final sink = algorithm.newMacSinkSync(
                secretKeyData: secretKeyData,
              );
              final n = slice.length ~/ 3;
              sink.addSlice(slice, 0, n, false);
              sink.addSlice(slice, n, 2 * n, false);
              sink.addSlice(slice, 2 * n, slice.length, true);
              expect(
                sink.macSync().bytes,
                packageCryptoHash,
              );
            }
          }
        }
      },
      testOn: 'vm',
      timeout: Timeout.factor(10),
    );
  });
}
