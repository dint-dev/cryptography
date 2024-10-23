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

/// [AesGcm] that's optimized to use [compute].
class BackgroundAesGcm extends AesGcm with BackgroundCipherMixin {
  @override
  final int nonceLength;

  @override
  final CryptographyChannelPolicy channelPolicy;

  @override
  late AesGcm fallback = Cryptography.defaultInstance.aesGcm(
    nonceLength: nonceLength,
    secretKeyLength: secretKeyLength,
  );

  @override
  final int secretKeyLength;

  /// Constructs [AesGcm] that's optimized to use [compute].
  ///
  /// The [channelPolicy] can be used to choose which computations are done in
  /// the background and which computations are not.
  /// The default [FlutterCipher.defaultChannelPolicy] forces small [encrypt] /
  /// [decrypt] call to be computed in the same isolate.
  ///
  /// If you want deterministic key generation for testing, you can pass a
  /// [Random] instance that returns the same sequence of bytes every time.
  /// However, this disables the use of [compute].
  BackgroundAesGcm({
    required this.secretKeyLength,
    this.nonceLength = AesGcm.defaultNonceLength,
    CryptographyChannelPolicy? channelPolicy,
    Random? random,
  })  : assert(secretKeyLength == 16 ||
            secretKeyLength == 24 ||
            secretKeyLength == 32),
        channelPolicy = random != null
            ? CryptographyChannelPolicy.never
            : (channelPolicy ?? BackgroundCipher.defaultChannelPolicy),
        super.constructor(random: random);

  BackgroundAesGcm.with128bits({
    int nonceLength = AesGcm.defaultNonceLength,
  }) : this(secretKeyLength: 16, nonceLength: nonceLength);

  BackgroundAesGcm.with192bits({
    int nonceLength = AesGcm.defaultNonceLength,
  }) : this(secretKeyLength: 24, nonceLength: nonceLength);

  BackgroundAesGcm.with256bits({
    int nonceLength = AesGcm.defaultNonceLength,
  }) : this(secretKeyLength: 32, nonceLength: nonceLength);

  @override
  Future<List> dispatchBackgroundDecrypt(List args) async {
    return await compute(
      _computeDecrypt,
      [secretKeyLength, nonceLength, ...args],
      debugLabel: 'BackgroundAesGcm.decrypt',
    );
  }

  @override
  Future<List> dispatchBackgroundEncrypt(List args) async {
    return await compute(
      _computeEncrypt,
      [secretKeyLength, nonceLength, ...args],
      debugLabel: 'BackgroundAesGcm.encrypt',
    );
  }

  static Future<List> _computeDecrypt(List args) async {
    final secretKeyLength = args[0] as int;
    final nonceLength = args[1] as int;
    return await BackgroundCipher.receivedDecrypt(
      DartAesGcm(
        secretKeyLength: secretKeyLength,
        nonceLength: nonceLength,
      ),
      args.skip(2).toList(),
    );
  }

  static Future<List> _computeEncrypt(List args) async {
    final secretKeyLength = args[0] as int;
    final nonceLength = args[1] as int;
    return await BackgroundCipher.receivedEncrypt(
      DartAesGcm(
        secretKeyLength: secretKeyLength,
        nonceLength: nonceLength,
      ),
      args.skip(2).toList(),
    );
  }
}
