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

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart';
import 'package:cryptography/helpers.dart';
import 'package:flutter/foundation.dart';

import '../_internal.dart';

/// [X25519] that's optimized to use [compute].
class BackgroundX25519 extends DelegatingKeyExchangeAlgorithm
    implements X25519 {
  @override
  final X25519 fallback;

  final bool _allowBackground;

  BackgroundX25519({
    Random? random,
  })  : _allowBackground = random == null,
        fallback = DartX25519(random: random);

  @override
  KeyPairType<KeyPairData, PublicKey> get keyPairType => fallback.keyPairType;

  @override
  Future<SimpleKeyPair> newKeyPair() async {
    //
    // We observed that it's much faster compute this in the same isolate.
    //
    return (await super.newKeyPair()) as SimpleKeyPair;
    // final result = await compute(
    //   _computeNewKeyPair,
    //   0,
    //   debugLabel: 'BackgroundX25519.newKeyPair',
    // );
    // final privateKeyBytes = asUint8List(result[0]);
    // final publicKeyBytes = asUint8List(result[1]);
    // return SimpleKeyPairData(
    //   privateKeyBytes,
    //   publicKey: SimplePublicKey(
    //     publicKeyBytes,
    //     type: KeyPairType.x25519,
    //   ),
    //   type: KeyPairType.x25519,
    // );
  }

  @override
  Future<SimpleKeyPair> newKeyPairFromSeed(List<int> seed) {
    return fallback.newKeyPairFromSeed(seed);
  }

  @override
  Future<SecretKey> sharedSecretKey({
    required KeyPair keyPair,
    required PublicKey remotePublicKey,
  }) async {
    if (!_allowBackground) {
      return await super.sharedSecretKey(
        keyPair: keyPair,
        remotePublicKey: remotePublicKey,
      );
    }
    final privateKey = await keyPair.extract() as SimpleKeyPairData;
    final publicKey = await keyPair.extractPublicKey() as SimplePublicKey;
    final result = await compute(
      _computeSharedSecretKey,
      [
        asUint8List(privateKey.bytes),
        asUint8List(publicKey.bytes),
        asUint8List((remotePublicKey as SimplePublicKey).bytes),
      ],
      debugLabel: 'BackgroundX25519.sharedSecretKey',
    );
    final errorMessage = result[0] as String?;
    if (errorMessage != null) {
      throw StateError('$runtimeType.sharedSecretKey failed: $errorMessage');
    }
    return SecretKey(result[1] as Uint8List);
  }

  Future<List> _computeSharedSecretKey(List list) async {
    try {
      final privateKey = list[0] as Uint8List;
      final publicKey = list[1] as Uint8List;
      final remotePublicKey = list[2] as Uint8List;
      final result = await const DartX25519().sharedSecretKey(
        keyPair: SimpleKeyPairData(
          privateKey,
          publicKey: SimplePublicKey(
            publicKey,
            type: KeyPairType.x25519,
          ),
          type: KeyPairType.x25519,
        ),
        remotePublicKey: SimplePublicKey(
          remotePublicKey,
          type: KeyPairType.x25519,
        ),
      );
      return [null, asUint8List(await result.extractBytes())];
    } catch (error, stackTrace) {
      return ['$error\n$stackTrace'];
    }
  }

// static Future<List> _computeNewKeyPair(int arg) async {
//   final keyPair = await const DartX25519().newKeyPair() as SimpleKeyPairData;
//   final publicKey = await keyPair.extractPublicKey();
//   return [
//     asUint8List(keyPair.bytes),
//     asUint8List(publicKey.bytes),
//   ];
// }
}
