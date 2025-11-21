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

import 'package:cryptography/cryptography.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import '../../cryptography_flutter.dart';
import '../_flutter_cryptography_implementation.dart';
import '../_internal.dart';

/// [Ecdh] that uses platform APIs in Android, iOS, and Mac OS X.
class FlutterEcdh extends Ecdh implements PlatformCryptographicAlgorithm {
  final int length;

  @override
  final Ecdh? fallback;

  /// Optional Android provider name (such as "BC").
  final String? androidCryptoProvider;

  @override
  final KeyPairType<KeyPairData, PublicKey> keyPairType;

  /// ECDH-P256
  FlutterEcdh.p256({
    this.length = 32,
    this.androidCryptoProvider,
    this.fallback,
  })  : keyPairType = KeyPairType.p256,
        super.constructor();

  /// ECDH-P384
  FlutterEcdh.p384({
    this.length = 32,
    this.androidCryptoProvider,
    this.fallback,
  })  : keyPairType = KeyPairType.p384,
        super.constructor();

  /// ECDH-P521
  FlutterEcdh.p521({
    this.length = 32,
    this.androidCryptoProvider,
    this.fallback,
  })  : keyPairType = KeyPairType.p521,
        super.constructor();

  @override
  bool get isSupportedPlatform =>
      FlutterCryptography.isPluginPresent && (isAndroid || isCupertino);

  String get _curveName {
    switch (keyPairType) {
      case KeyPairType.p256:
        return 'p256';
      case KeyPairType.p384:
        return 'p384';
      case KeyPairType.p521:
        return 'p521';
      default:
        throw StateError('Unsupported key pair type: $keyPairType');
    }
  }

  @override
  Future<EcKeyPair> newKeyPair() async {
    if (isSupportedPlatform) {
      final result = await invokeMethod(
        'Ecdh.newKeyPair',
        {
          if (isAndroid) 'androidProvider': androidCryptoProvider,
          'curve': _curveName,
        },
      );
      final der = result['der'] as Uint8List?;
      if (der != null) {
        return EcKeyPairData.parseDer(
          der,
          type: keyPairType,
        );
      }
      final d = result['d'] as Uint8List;
      final x = result['x'] as Uint8List;
      final y = result['y'] as Uint8List;
      return EcKeyPairData(
        d: d,
        x: x,
        y: y,
        type: keyPairType,
      );
    }
    final fallback = this.fallback;
    if (fallback == null) {
      throw UnsupportedError('Unsupported and no fallback implementation');
    }
    return await fallback.newKeyPair();
  }

  @override
  Future<EcKeyPair> newKeyPairFromSeed(List<int> seed) async {
    if (isSupportedPlatform) {
      final result = await invokeMethod(
        'Ecdh.newKeyPair',
        {
          if (isAndroid) 'androidProvider': androidCryptoProvider,
          'curve': _curveName,
          'seed': asUint8List(seed),
        },
      );
      final der = result['der'] as Uint8List?;
      if (der != null) {
        return EcKeyPairData.parseDer(
          der,
          type: keyPairType,
        );
      }
      final d = result['d'] as Uint8List;
      final x = result['x'] as Uint8List;
      final y = result['y'] as Uint8List;
      return EcKeyPairData(
        d: d,
        x: x,
        y: y,
        type: keyPairType,
      );
    }
    final fallback = this.fallback;
    if (fallback == null) {
      throw UnsupportedError('Unsupported and no fallback implementation');
    }
    return await fallback.newKeyPair();
  }

  @override
  Future<SecretKey> sharedSecretKey({
    required KeyPair keyPair,
    required PublicKey remotePublicKey,
  }) async {
    if (isSupportedPlatform) {
      final keyPairData = await keyPair.extract();
      if (keyPairData is! EcKeyPairData) {
        throw ArgumentError.value(
          keyPair,
          'keyPair',
          'Expected EcKeyPair',
        );
      }
      if (remotePublicKey is! EcPublicKey) {
        throw ArgumentError.value(
          remotePublicKey,
          'remotePublicKey',
          'Expected EcPublicKey',
        );
      }
      Map result;
      if (isCupertino) {
        result = await invokeMethod(
          'Ecdh.sharedSecretKey',
          {
            if (isAndroid) 'androidProvider': androidCryptoProvider,
            'curve': _curveName,
            'localDer': keyPairData.toDer(),
            'remoteDer': remotePublicKey.toDer(),
          },
        );
      } else {
        result = await invokeMethod(
          'Ecdh.sharedSecretKey',
          {
            if (isAndroid) 'androidProvider': androidCryptoProvider,
            'curve': _curveName,
            'localD': asUint8List(keyPairData.d),
            'localX': asUint8List(keyPairData.x),
            'localY': asUint8List(keyPairData.y),
            'remoteX': asUint8List(remotePublicKey.x),
            'remoteY': asUint8List(remotePublicKey.y),
          },
        );
      }
      final error = result['error'];
      if (error != null) {
        throw StateError(
          '"package:cryptography_flutter": invalid output from plugin: $error',
        );
      }
      var bytes = result['bytes'] as Uint8List;
      if (bytes.length >= length) {
        if (bytes.length > length) {
          bytes = bytes.sublist(0, length);
        }
        return SecretKey(bytes);
      }
    }
    final fallback = this.fallback;
    if (fallback == null) {
      throw UnsupportedError('Unsupported and no fallback implementation');
    }
    return await fallback.sharedSecretKey(
      keyPair: keyPair,
      remotePublicKey: remotePublicKey,
    );
  }
}
