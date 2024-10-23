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

import 'dart:async';

import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:cryptography_flutter_plus/cryptography_flutter_plus.dart';
import 'package:flutter/foundation.dart';

import '../_internal.dart';

/// Base class for ciphers that use background workers.
abstract class BackgroundCipher implements Cipher {
  /// Experimentally determined default [CryptographyChannelPolicy].
  static final CryptographyChannelPolicy defaultChannelPolicy =
      CryptographyChannelPolicy(
    minLength: 10 * 1000,
    maxLength: CryptographyChannelQueue.defaultInstance.maxConcurrentSize,
  );

  /// Uses [compute] to do decryption in the background.
  @protected
  Future<List> dispatchBackgroundDecrypt(List args);

  /// Uses [compute] to do encryption in the background.
  @protected
  Future<List> dispatchBackgroundEncrypt(List args);

  @override
  Stream<List<int>> encryptStream(
    Stream<List<int>> stream, {
    required SecretKey secretKey,
    required List<int> nonce,
    required void Function(Mac mac) onMac,
    List<int> aad = const [],
    bool allowUseSameBytes = false,
  }) {
    // Currently streaming must be done in the main thread.
    return toSync().encryptStream(
      stream,
      secretKey: secretKey,
      nonce: nonce,
      onMac: onMac,
      aad: aad,
      allowUseSameBytes: allowUseSameBytes,
    );
  }

  @override
  Stream<List<int>> decryptStream(
    Stream<List<int>> stream, {
    required SecretKey secretKey,
    required List<int> nonce,
    required FutureOr<Mac> mac,
    List<int> aad = const [],
    bool allowUseSameBytes = false,
  }) {
    // Currently streaming must be done in the main thread.
    return toSync().decryptStream(
      stream,
      secretKey: secretKey,
      nonce: nonce,
      mac: mac,
      aad: aad,
      allowUseSameBytes: allowUseSameBytes,
    );
  }

  @override
  CipherState newState() {
    // Currently streaming must be done in the main thread.
    return toSync().newState();
  }

  /// A helper for implementing isolate channel RPC.
  static Future<List> receivedDecrypt(Cipher cipher, List args) async {
    SecretKey? secretKey;
    try {
      final cipherText = args[0] as Uint8List;
      final secretKeyBytes = args[1] as Uint8List;
      secretKey = SecretKeyData(
        secretKeyBytes,
        overwriteWhenDestroyed: true,
      );
      final nonce = args[2] as Uint8List;
      final macBytes = args[3] as Uint8List;
      final mac = Mac(macBytes);
      final aad = args[4] as Uint8List;
      final secretBox = SecretBox(
        cipherText,
        nonce: nonce,
        mac: mac,
      );
      final result = await cipher.decrypt(
        secretBox,
        secretKey: secretKey,
        aad: aad,
      );
      return [
        null, // The first object in the returned list is error message.
        result,
      ];
    } on SecretBoxAuthenticationError {
      return ['AUTHENTICATION_ERROR'];
    } on SecretBoxPaddingError {
      return ['PADDING_ERROR'];
    } catch (error, stackTrace) {
      // The first object in the returned list is error message.
      return ['Error: $error\n$stackTrace'];
    } finally {
      secretKey?.destroy();
    }
  }

  /// A helper for implementing isolate channel RPC.
  static Future<List> receivedEncrypt(Cipher cipher, List args) async {
    SecretKey? secretKey;
    try {
      final clearText = args[0] as Uint8List;
      final secretKeyBytes = args[1] as Uint8List;
      secretKey = SecretKeyData(
        secretKeyBytes,
        overwriteWhenDestroyed: true,
      );
      final nonce = args[2] as Uint8List;
      final aad = args[3] as Uint8List;
      final secretBox = await cipher.encrypt(
        clearText,
        secretKey: secretKey,
        nonce: nonce,
        aad: aad,
      );
      return [
        null, // The first object in the returned list is error message.
        secretBox.cipherText,
        secretBox.mac.bytes,
      ];
    } catch (error, stackTrace) {
      // The first object in the returned list is error message.
      return ['Error: $error\n$stackTrace'];
    } finally {
      secretKey?.destroy();
    }
  }
}

mixin BackgroundCipherMixin implements BackgroundCipher {
  CryptographyChannelPolicy get channelPolicy;

  Cipher get fallback;

  @override
  Future<List<int>> decrypt(
    SecretBox secretBox, {
    required SecretKey secretKey,
    List<int> aad = const <int>[],
    int keyStreamIndex = 0,
    Uint8List? possibleBuffer,
  }) async {
    if (kIsWeb || !channelPolicy.matches(length: secretBox.cipherText.length)) {
      return await fallback.decrypt(
        secretBox,
        secretKey: secretKey,
        aad: aad,
      );
    }
    final cipherText = secretBox.cipherText;
    final nonce = secretBox.nonce;
    final mac = secretBox.mac.bytes;
    if (nonce.length != nonceLength) {
      throw ArgumentError.value(
        nonce,
        'nonce',
        'Nonce should be $nonceLength bytes long, not ${nonce.length} bytes.',
      );
    }
    if (mac.length != macAlgorithm.macLength) {
      throw SecretBoxAuthenticationError();
    }
    final secretKeyBytes = await secretKey.extractBytes();
    if (secretKeyBytes.length != secretKeyLength) {
      throw ArgumentError.value(
        secretKey,
        'secretKey',
        'Secret key should be $secretKeyLength bytes long, not ${secretKeyBytes.length} bytes.',
      );
    }
    final args = [
      asUint8List(cipherText),
      asUint8List(secretKeyBytes),
      asUint8List(nonce),
      asUint8List(mac),
      asUint8List(aad),
    ];
    final size = CryptographyChannelQueue.estimateSize(args);
    final queue = CryptographyChannelQueue.defaultInstance;
    final lock = queue.newLock(size: size);
    await lock.lock();
    List result;
    try {
      result = await dispatchBackgroundDecrypt(args);
    } finally {
      lock.unlock();
    }
    final errorMessage = result[0] as String?;
    if (errorMessage != null) {
      switch (errorMessage) {
        case 'AUTHENTICATION_ERROR':
          throw SecretBoxAuthenticationError();
        case 'PADDING_ERROR':
          throw SecretBoxPaddingError();
        default:
          throw StateError('$runtimeType.decrypt failed: $errorMessage');
      }
    }
    final clearText = result[1] as Uint8List;

    // Sanity check
    if (cipherText.length != cipherTextLength(clearText.length)) {
      throw StateError(
        '$runtimeType.decrypt sanity check failed: '
        'clearText.length (${clearText.length}) != '
        'cipherText.length (${cipherText.length})',
      );
    }

    return clearText;
  }

  @override
  Future<SecretBox> encrypt(
    List<int> clearText, {
    required SecretKey secretKey,
    List<int>? nonce,
    List<int> aad = const <int>[],
    int keyStreamIndex = 0,
    Uint8List? possibleBuffer,
  }) async {
    if (kIsWeb || !channelPolicy.matches(length: clearText.length)) {
      return await fallback.encrypt(
        clearText,
        secretKey: secretKey,
        nonce: nonce,
        aad: aad,
      );
    }
    nonce ??= newNonce();
    if (nonce.length != nonceLength) {
      throw ArgumentError.value(
        nonce,
        'nonce',
        'Nonce should be $nonceLength bytes long, not ${nonce.length} bytes.',
      );
    }
    final secretKeyBytes = await secretKey.extractBytes();
    if (secretKeyBytes.length != secretKeyLength) {
      throw ArgumentError.value(
        secretKey,
        'secretKey',
        'Secret key should be $secretKeyLength bytes long, not ${secretKeyBytes.length} bytes.',
      );
    }
    final args = [
      asUint8List(clearText),
      asUint8List(secretKeyBytes),
      asUint8List(nonce),
      asUint8List(aad),
    ];
    final size = CryptographyChannelQueue.estimateSize(args);
    final queue = CryptographyChannelQueue.defaultInstance;
    final lock = queue.newLock(size: size);
    await lock.lock();
    List result;
    try {
      result = await dispatchBackgroundEncrypt(args);
    } finally {
      lock.unlock();
    }
    final errorMessage = result[0] as String?;
    if (errorMessage != null) {
      throw StateError('$runtimeType.encrypt failed: $errorMessage');
    }
    final cipherText = result[1] as Uint8List;
    final macBytes = result[2] as Uint8List;

    // Sanity check
    if (cipherText.length != cipherTextLength(clearText.length)) {
      throw StateError(
        '$runtimeType.encrypt sanity check failed: '
        'cipherText.length (${cipherText.length}) != '
        'clearText.length (${clearText.length})',
      );
    }

    return SecretBox(
      cipherText,
      nonce: nonce,
      mac: Mac(macBytes),
    );
  }
}
