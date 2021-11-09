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

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/helpers.dart';

import 'internal.dart';

Future<List<int>> _decryptWithPlugin(
  FlutterCipher cipher,
  SecretBox secretBox, {
  required SecretKey secretKey,
  required List<int> aad,
}) async {
  final secretKeyBytes = await secretKey.extractBytes();
  final result = await invokeMethod(
    'decrypt',
    <String, Object>{
      'algo': cipher.pluginCipherName,
      'cipherText': Uint8List.fromList(secretBox.cipherText),
      'secretKey': Uint8List.fromList(secretKeyBytes),
      'nonce': Uint8List.fromList(secretBox.nonce),
      'mac': Uint8List.fromList(secretBox.mac.bytes),
    },
  );
  return result['clearText'] as Uint8List;
}

Future<SecretBox> _encryptWithPlugin(
  FlutterCipher cipher,
  List<int> clearText, {
  required SecretKey secretKey,
  required List<int>? nonce,
  required List<int> aad,
}) async {
  nonce ??= cipher.newNonce();
  final secretKeyData = await secretKey.extract();
  final result = await invokeMethod(
    'encrypt',
    <String, Object>{
      'algo': cipher.pluginCipherName,
      'clearText': Uint8List.fromList(clearText),
      'secretKey': Uint8List.fromList(secretKeyData.bytes),
      'nonce': Uint8List.fromList(nonce),
    },
  );
  final cipherText = result['cipherText'] as Uint8List;
  var mac = Mac.empty;
  if (result.containsKey('mac')) {
    mac = Mac(List<int>.unmodifiable(result['mac'] as Uint8List));
  }
  return SecretBox(cipherText, nonce: nonce, mac: mac);
}

abstract class FlutterCipher extends DelegatingCipher
    with FlutterCryptographyImplementation {
  late bool usePlugin = isSupportedPlatform;

  bool get isSupportedPlatform;

  String get pluginCipherName;

  @override
  Future<List<int>> decrypt(
    SecretBox secretBox, {
    required SecretKey secretKey,
    List<int> aad = const <int>[],
  }) async {
    if (usePlugin) {
      try {
        return await _decryptWithPlugin(
          this,
          secretBox,
          secretKey: secretKey,
          aad: aad,
        );
      } catch (error, stackTrace) {
        usePlugin = false;
        reportError(error, stackTrace);
      }
    }
    return super.decrypt(
      secretBox,
      secretKey: secretKey,
      aad: aad,
    );
  }

  @override
  Future<SecretBox> encrypt(
    List<int> clearText, {
    required SecretKey secretKey,
    List<int>? nonce,
    List<int> aad = const <int>[],
  }) async {
    if (usePlugin) {
      try {
        return await _encryptWithPlugin(
          this,
          clearText,
          secretKey: secretKey,
          nonce: nonce,
          aad: aad,
        );
      } catch (error, stackTrace) {
        usePlugin = false;
        reportError(error, stackTrace);
      }
    }
    return super.encrypt(
      clearText,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
    );
  }
}

abstract class FlutterStreamingCipher extends DelegatingStreamingCipher
    with FlutterCryptographyImplementation
    implements FlutterCipher {
  @override
  late bool usePlugin = isSupportedPlatform;

  @override
  bool get isSupportedPlatform;

  @override
  String get pluginCipherName;

  @override
  Future<List<int>> decrypt(
    SecretBox secretBox, {
    required SecretKey secretKey,
    List<int> aad = const <int>[],
    int keyStreamIndex = 0,
  }) async {
    if (keyStreamIndex == 0 && usePlugin) {
      try {
        await _decryptWithPlugin(
          this,
          secretBox,
          secretKey: secretKey,
          aad: aad,
        );
      } catch (error, stackTrace) {
        usePlugin = false;
        reportError(error, stackTrace);
      }
    }
    return super.decrypt(
      secretBox,
      secretKey: secretKey,
      aad: aad,
      keyStreamIndex: keyStreamIndex,
    );
  }

  @override
  Future<SecretBox> encrypt(
    List<int> clearText, {
    required SecretKey secretKey,
    List<int>? nonce,
    List<int> aad = const <int>[],
    int keyStreamIndex = 0,
  }) async {
    if (keyStreamIndex == 0 && usePlugin) {
      try {
        return await _encryptWithPlugin(
          this,
          clearText,
          secretKey: secretKey,
          nonce: nonce,
          aad: aad,
        );
      } catch (error, stackTrace) {
        usePlugin = false;
        reportError(error, stackTrace);
      }
    }
    return super.encrypt(
      clearText,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
      keyStreamIndex: keyStreamIndex,
    );
  }
}
