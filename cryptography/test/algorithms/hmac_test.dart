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

import 'package:cryptography/browser.dart';
import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart';
import 'package:cryptography/src/utils.dart';
import 'package:test/test.dart';

void main() {
  group('Hmac:', () {
    group('DartCryptography:', () {
      setUp(() {
        Cryptography.instance = DartCryptography.defaultInstance;
      });
      _main();
    });
    group('BrowserCryptography:', () {
      setUp(() {
        Cryptography.instance = BrowserCryptography.defaultInstance;
      });
      _main();
    });
  });
}

void _main() {
  late Hmac hmac;
  setUp(() {
    hmac = Hmac(Sha256());
  });

  test('toString()', () {
    expect(Hmac(Sha1()).toString(), 'Hmac(Sha1())');
    expect(Hmac(Sha224()).toString(), 'Hmac(Sha224())');
    expect(Hmac(Sha256()).toString(), 'Hmac.sha256()');
    expect(Hmac(Sha384()).toString(), 'Hmac(Sha384())');
    expect(Hmac(Sha512()).toString(), 'Hmac.sha512()');
  });

  test('hashAlgorithm', () {
    expect(
      Hmac(Sha224()).hashAlgorithm,
      same(Sha224()),
    );
    expect(
      Hmac(Sha256()).hashAlgorithm,
      same(Sha256()),
    );
  });

  test('newSink(): empty key fails', () async {
    final secretKey = SecretKey(<int>[]);
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

  test('calculateMac(...): different secretKey and data lengths', () async {
    for (var n = 1; n < 1024; n++) {
      final secretKey = SecretKey(Uint8List(n));
      final data = Uint8List(n);
      for (var i = 0; i < data.length; i++) {
        data[i] = 0xFF & i;
      }

      // ignore: unused_local_variable
      final mac = await hmac.calculateMac(
        data,
        secretKey: secretKey,
        nonce: const <int>[],
      );

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
  });

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

      test('sha224', () async {
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

      test('sha256', () async {
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

      test('sha384', () async {
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

      test('sha512', () async {
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
  });
}
