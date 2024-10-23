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
import 'package:flutter/services.dart';

import '../../cryptography_flutter_plus.dart';
import '../_flutter_cryptography_implementation.dart';
import '../_internal.dart';

/// [Ecdsa] that uses platform APIs in Android, iOS, and Mac OS X.
class FlutterEcdsa extends Ecdsa implements PlatformCryptographicAlgorithm {
  @override
  final Ecdsa? fallback;

  /// Optional Android provider name (such as "BC").
  final String? androidCryptoProvider;

  @override
  HashAlgorithm hashAlgorithm;

  @override
  final KeyPairType<KeyPairData, PublicKey> keyPairType;

  /// ECDSA-P256
  FlutterEcdsa.p256(
    this.hashAlgorithm, {
    this.androidCryptoProvider,
    this.fallback,
  })  : keyPairType = KeyPairType.p256,
        super.constructor();

  /// ECDSA-P384
  FlutterEcdsa.p384(
    this.hashAlgorithm, {
    this.androidCryptoProvider,
    this.fallback,
  })  : keyPairType = KeyPairType.p384,
        super.constructor();

  /// ECDSA-P521
  FlutterEcdsa.p521(
    this.hashAlgorithm, {
    this.androidCryptoProvider,
    this.fallback,
  })  : keyPairType = KeyPairType.p521,
        super.constructor();

  @override
  bool get isSupportedPlatform =>
      FlutterCryptography.isPluginPresent && isCupertino;

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
        'Ecdsa.newKeyPair',
        {
          if (isAndroid) 'androidProvider': androidCryptoProvider,
          'curve': keyPairType.name,
        },
      );
      final der = result['der'] as Uint8List?;
      if (der != null) {
        // if (keyPairType==KeyPairType.p384) {
        //   throw StateError('public key DER:\n${hexFromBytes(generatedPublicDer!)}');
        // }
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
    return fallback.newKeyPair();
  }

  @override
  Future<EcKeyPair> newKeyPairFromSeed(List<int> seed) async {
    if (isSupportedPlatform) {
      final result = await invokeMethod(
        'Ecdsa.newKeyPairFromSeed',
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
  Future<Signature> sign(
    List<int> message, {
    required KeyPair keyPair,
  }) async {
    if (isSupportedPlatform) {
      final keyPairData = await keyPair.extract();
      if (keyPairData is! EcKeyPairData) {
        throw ArgumentError.value(
          keyPairData,
          'keyPair',
        );
      }
      Map result;
      if (isCupertino) {
        result = await invokeMethod(
          'Ecdsa.sign',
          {
            if (isAndroid) 'androidProvider': androidCryptoProvider,
            'curve': _curveName,
            'data': Uint8List.fromList(message),
            'der': keyPairData.toDer(),
          },
        );
      } else {
        result = await invokeMethod(
          'Ecdsa.sign',
          {
            if (isAndroid) 'androidProvider': androidCryptoProvider,
            'curve': _curveName,
            'data': Uint8List.fromList(message),
            'd': asUint8List(keyPairData.d),
            'x': asUint8List(keyPairData.x),
            'y': asUint8List(keyPairData.y),
          },
        );
      }
      final error = result['error'] as String?;
      if (error != null) {
        throw StateError(
          '"package:cryptography_flutter": $runtimeType.sign failed: $error',
        );
      }
      final signature = result['signature'] as Uint8List;
      final publicKey = await keyPairData.extractPublicKey();
      return Signature(signature, publicKey: publicKey);
    }
    final fallback = this.fallback;
    if (fallback == null) {
      throw UnsupportedError('Unsupported and no fallback implementation');
    }
    return await fallback.sign(
      message,
      keyPair: keyPair,
    );
  }

  @override
  Future<bool> verify(List<int> message, {required Signature signature}) async {
    if (isSupportedPlatform) {
      final publicKey = signature.publicKey;
      if (publicKey is! EcPublicKey) {
        throw ArgumentError.value(
          signature,
          'signature',
        );
      }
      Map result;
      if (isCupertino) {
        try {
          result = await invokeMethod(
            'Ecdsa.verify',
            {
              if (isAndroid) 'androidProvider': androidCryptoProvider,
              'curve': _curveName,
              'data': asUint8List(message),
              'signature': asUint8List(signature.bytes),
              'der': publicKey.toDer(),
            },
          );
        } on PlatformException {
          rethrow;
        }
      } else {
        result = await invokeMethod(
          'Ecdsa.verify',
          {
            if (isAndroid) 'androidProvider': androidCryptoProvider,
            'curve': _curveName,
            'data': asUint8List(message),
            'signature': asUint8List(signature.bytes),
            'x': asUint8List(publicKey.x),
            'y': asUint8List(publicKey.y),
          },
        );
      }
      final error = result['error'];
      if (error != null) {
        throw StateError(
          '"package:cryptography_flutter": $runtimeType.verify failed: $error',
        );
      }
      return result['result'] as bool;
    }
    final fallback = this.fallback;
    if (fallback == null) {
      throw UnsupportedError('Unsupported and no fallback implementation');
    }
    return await fallback.verify(
      message,
      signature: signature,
    );
  }
}
