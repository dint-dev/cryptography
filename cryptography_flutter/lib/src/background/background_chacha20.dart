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

import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:cryptography_plus/dart.dart';
import 'package:flutter/foundation.dart';

import '../../cryptography_flutter_plus.dart';

/// [Chacha20.poly1305Aead] that's optimized to use [compute].
class BackgroundChacha extends Chacha20 with BackgroundCipherMixin {
  @override
  final CryptographyChannelPolicy channelPolicy;

  @override
  late Cipher fallback = Cryptography.defaultInstance.chacha20Poly1305Aead();

  /// Constructs [Chacha20.poly1305Aead] that's optimized to use [compute].
  ///
  /// The [channelPolicy] can be used to choose which computations are done in
  /// the background and which computations are not.
  /// The default [FlutterCipher.defaultChannelPolicy] forces small [encrypt] /
  /// [decrypt] call to be computed in the same isolate.
  ///
  /// If you want deterministic key generation for testing, you can pass a
  /// [Random] instance that returns the same sequence of bytes every time.
  /// However, this disables the use of [compute].
  BackgroundChacha.poly1305Aead({
    CryptographyChannelPolicy? channelPolicy,
    Random? random,
  })  : channelPolicy = random != null
            ? CryptographyChannelPolicy.never
            : (channelPolicy ?? BackgroundCipher.defaultChannelPolicy),
        super.constructor(random: random);

  @override
  MacAlgorithm get macAlgorithm => const DartChacha20Poly1305AeadMacAlgorithm();

  @override
  Future<List> dispatchBackgroundDecrypt(List args) async {
    return await compute(
      _computeDecrypt,
      args,
      debugLabel: 'BackgroundChacha20Poly1305Aead.decrypt',
    );
  }

  @override
  Future<List> dispatchBackgroundEncrypt(List args) async {
    return await compute(
      _computeEncrypt,
      args,
      debugLabel: 'BackgroundChacha20Poly1305Aead.encrypt',
    );
  }

  static Future<List> _computeDecrypt(List args) async {
    return BackgroundCipher.receivedDecrypt(
      const DartChacha20.poly1305Aead(),
      args,
    );
  }

  static Future<List> _computeEncrypt(List args) async {
    return BackgroundCipher.receivedEncrypt(
      const DartChacha20.poly1305Aead(),
      args,
    );
  }
}
