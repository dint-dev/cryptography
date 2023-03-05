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

/// [Ed25519] that's optimized to use [compute].
class BackgroundEd25519 extends DelegatingEd25519 implements Ed25519 {
  @override
  final Ed25519 fallback;

  final bool _allowBackground;

  BackgroundEd25519({
    Random? random,
  })  : _allowBackground = random == null,
        fallback = DartEd25519(random: random);

  @override
  Future<SimpleKeyPair> newKeyPair() async {
    //
    // We observed that it's much faster to do it in the same isolate.
    //
    return await super.newKeyPair();
    // final result = await compute(
    //   _computeNewKeyPair,
    //   0,
    //   debugLabel: 'BackgroundEd25519.newKeyPair',
    // );
    // final privateKeyBytes = asUint8List(result[0]);
    // final publicKeyBytes = asUint8List(result[1]);
    // return SimpleKeyPairData(
    //   privateKeyBytes,
    //   publicKey: SimplePublicKey(
    //     publicKeyBytes,
    //     type: KeyPairType.ed25519,
    //   ),
    //   type: KeyPairType.ed25519,
    // );
  }

  @override
  Future<Signature> sign(List<int> message, {required KeyPair keyPair}) async {
    if (!_allowBackground) {
      return super.sign(
        message,
        keyPair: keyPair,
      );
    }
    if (keyPair is SimpleKeyPair) {
      final keyPairData = await keyPair.extract();
      final publicKey = await keyPairData.extractPublicKey();
      final result = await compute(
        _computeSign,
        [
          asUint8List(message),
          asUint8List(keyPairData.bytes),
          asUint8List(publicKey.bytes),
        ],
        debugLabel: '$runtimeType.sign',
      );
      final errorMessage = result.first as String?;
      if (errorMessage != null) {
        throw StateError('$runtimeType.sign() failed: $errorMessage');
      }
      return Signature(
        result[1] as Uint8List,
        publicKey: publicKey,
      );
    }
    return super.sign(
      message,
      keyPair: keyPair,
    );
  }

  @override
  Future<bool> verify(List<int> message, {required Signature signature}) async {
    if (!_allowBackground) {
      return super.verify(
        message,
        signature: signature,
      );
    }
    final publicKey = signature.publicKey;
    if (publicKey is SimplePublicKey) {
      final result = await compute(
        _computeVerify,
        [
          asUint8List(message),
          asUint8List(signature.bytes),
          asUint8List(publicKey.bytes),
        ],
        debugLabel: '$runtimeType.verify',
      );
      final errorMessage = result.first as String?;
      if (errorMessage != null) {
        throw StateError('$runtimeType.verify() failed: $errorMessage');
      }
      return result[1] as bool;
    }
    return super.verify(
      message,
      signature: signature,
    );
  }

  // static Future<List> _computeNewKeyPair(int arg) async {
  //   final keyPair = await DartEd25519().newKeyPair() as SimpleKeyPairData;
  //   final publicKey = await keyPair.extractPublicKey();
  //   return [
  //     asUint8List(keyPair.bytes),
  //     asUint8List(publicKey.bytes),
  //   ];
  // }

  static Future<List> _computeSign(List args) async {
    try {
      final message = args[0] as Uint8List;
      final privateKey = args[1] as Uint8List;
      final publicKey = args[2] as Uint8List;
      final keyPair = SimpleKeyPairData(
        privateKey,
        publicKey: SimplePublicKey(publicKey, type: KeyPairType.ed25519),
        type: KeyPairType.ed25519,
      );
      final signature = await DartEd25519().sign(
        message,
        keyPair: keyPair,
      );
      return [null, signature.bytes];
    } catch (error, stackTrace) {
      return ['$error\n$stackTrace'];
    }
  }

  static Future<List> _computeVerify(List args) async {
    try {
      final message = args[0] as Uint8List;
      final signature = args[1] as Uint8List;
      final publicKey = args[2] as Uint8List;
      final result = await DartEd25519().verify(
        message,
        signature: Signature(
          signature,
          publicKey: SimplePublicKey(
            publicKey,
            type: KeyPairType.ed25519,
          ),
        ),
      );
      return [null, result];
    } catch (error, stackTrace) {
      return ['$error\n$stackTrace'];
    }
  }
}
