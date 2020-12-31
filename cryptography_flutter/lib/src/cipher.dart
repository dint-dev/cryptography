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

import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart';
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
  final error = result['error'];
  if (error is String) {
    throw StateError(error);
  }
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
  final error = result['error'];
  if (error is String) {
    throw StateError(error);
  }
  final cipherText = result['cipherText'] as Uint8List;
  var mac = Mac.empty;
  if (result.containsKey('mac')) {
    mac = Mac(List<int>.unmodifiable(result['mac'] as Uint8List));
  }
  return SecretBox(cipherText, nonce: nonce, mac: mac);
}

class FlutterAesCbc extends FlutterCipher implements AesCbc {
  @override
  final AesCbc fallback;

  @override
  FlutterAesCbc(this.fallback);

  @override
  bool get isSupportedPlatform => Platform.isAndroid;

  @override
  String get pluginCipherName => 'AesCbc';

  @override
  int get secretKeyLength => fallback.secretKeyLength;
}

class FlutterAesCtr extends FlutterStreamingCipher implements AesCtr {
  @override
  final AesCtr fallback;

  FlutterAesCtr(this.fallback);

  @override
  int get counterBits => fallback.counterBits;

  @override
  bool get isSupportedPlatform => Platform.isAndroid;

  @override
  String get pluginCipherName => 'AesCtr';

  @override
  int get secretKeyLength => fallback.secretKeyLength;
}

class FlutterAesGcm extends FlutterStreamingCipher implements AesGcm {
  @override
  final AesGcm fallback;

  FlutterAesGcm(this.fallback);

  @override
  bool get isSupportedPlatform =>
      Platform.isAndroid || Platform.isIOS || Platform.isMacOS;

  @override
  String get pluginCipherName => 'AesGcm';

  @override
  int get secretKeyLength => fallback.secretKeyLength;
}

class FlutterChacha20 extends FlutterStreamingCipher implements Chacha20 {
  @override
  final Chacha20 fallback;

  FlutterChacha20(this.fallback);

  @override
  bool get isSupportedPlatform =>
      (Platform.isAndroid || Platform.isIOS || Platform.isMacOS) &&
      macAlgorithm is DartChacha20Poly1305AeadMacAlgorithm;

  @override
  String get pluginCipherName => 'Chacha20.poly1305Aead';
}

abstract class FlutterCipher extends DelegatingCipher {
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
        return _decryptWithPlugin(
          this,
          secretBox,
          secretKey: secretKey,
          aad: aad,
        );
      } catch (error) {
        usePlugin = false;
        reportError(error);
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
        return _encryptWithPlugin(
          this,
          clearText,
          secretKey: secretKey,
          nonce: nonce,
          aad: aad,
        );
      } catch (error) {
        usePlugin = false;
        reportError(error);
      }
    }
    return super.encrypt(
      clearText,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
    );
  }

  void reportError(Object error) {
    if (error is UnsupportedError) {
      return;
    }
    print('"package:cryptography_flutter": error: $error');
  }
}

abstract class FlutterStreamingCipher extends DelegatingStreamingCipher
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
        return _decryptWithPlugin(
          this,
          secretBox,
          secretKey: secretKey,
          aad: aad,
        );
      } catch (error) {
        usePlugin = false;
        reportError(error);
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
        return _encryptWithPlugin(
          this,
          clearText,
          secretKey: secretKey,
          nonce: nonce,
          aad: aad,
        );
      } catch (error) {
        usePlugin = false;
        reportError(error);
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

  @override
  void reportError(Object error) {
    if (error is UnsupportedError) {
      return;
    }
    print('"package:cryptography_flutter": error: $error');
  }
}
