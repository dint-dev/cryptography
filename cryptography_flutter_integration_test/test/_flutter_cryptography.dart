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
import 'package:cryptography_flutter_plus/cryptography_flutter_plus.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';

Matcher _unlessBrowser(Matcher matcher) {
  if (kIsWeb) {
    return isNot(matcher);
  }
  return matcher;
}

void testFlutterCryptography() {
  group('Cryptography.instance behavior:', () {
    test('is FlutterCryptography', () {
      expect(
        Cryptography.instance,
        _unlessBrowser(same(FlutterCryptography.defaultInstance)),
      );
    });

    test('AesGcm()', () {
      final instance = AesGcm.with256bits();
      expect(
        instance,
        _unlessBrowser(anyOf(
          isA<FlutterAesGcm>(),
          isA<BackgroundAesGcm>(),
        )),
      );
    });

    test('Chacha20.poly1305()', () {
      final instance = Chacha20.poly1305Aead();
      expect(
        instance,
        _unlessBrowser(anyOf(
          isA<FlutterChacha20>(),
          isA<BackgroundChacha>(),
        )),
      );
    });

    test('Ecdh.p256()', () {
      if (!FlutterEcdh.p256(length: 32).isSupportedPlatform) {
        return;
      }
      final instance = Ecdh.p256(length: 32);
      expect(
        instance,
        _unlessBrowser(isA<FlutterEcdh>()),
      );
    });

    test('Ecdh.p384()', () {
      if (!FlutterEcdh.p384(length: 32).isSupportedPlatform) {
        return;
      }
      final instance = Ecdh.p384(length: 32);
      expect(
        instance,
        _unlessBrowser(isA<FlutterEcdh>()),
      );
    });

    test('Ecdsa.p256()', () {
      if (!FlutterEcdsa.p256(Sha256()).isSupportedPlatform) {
        return;
      }
      final instance = Ecdsa.p256(Sha256());
      expect(
        instance,
        _unlessBrowser(isA<FlutterEcdsa>()),
      );
    });

    test('Ecdsa.p384()', () {
      if (!FlutterEcdsa.p384(Sha384()).isSupportedPlatform) {
        return;
      }
      final instance = Ecdsa.p384(Sha384());
      expect(
        instance,
        _unlessBrowser(isA<FlutterEcdsa>()),
      );
    });
  });
}
