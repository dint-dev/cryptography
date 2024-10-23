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
import 'package:flutter/services.dart';

import '../../cryptography_flutter_plus.dart';
import '../_internal.dart';

/// [AesGcm] that uses platform APIs in Android, iOS, and Mac OS X.
///
/// When operating system APIs are not available [fallback] is used. The
/// default fallback implementation is [BackgroundAesGcm].
class FlutterAesGcm extends AesGcm with FlutterCipherMixin {
  @override
  final AesGcm? fallback;

  @override
  final CryptographyChannelPolicy channelPolicy;

  @override
  final int secretKeyLength;

  /// Constructs Flutter-optimized [AesGcm] with the given [secretKeyLength].
  ///
  /// The [channelPolicy] can be used to choose which requests are sent to the
  /// plugin implementation (using a Flutter [MethodChannel]) and which ones are
  /// handled in the same isolate.
  /// The default [FlutterCipher.defaultChannelPolicy] forces small [encrypt] /
  /// [decrypt] calls to be handled in the same isolate.
  ///
  /// When operating system APIs are not available [fallback] is used. The
  /// default fallback implementation is [BackgroundAesGcm].
  ///
  /// If you want deterministic key generation for testing, you can pass a
  /// [Random] instance that returns the same sequence of bytes every time.
  FlutterAesGcm({
    required this.secretKeyLength,
    CryptographyChannelPolicy? channelPolicy,
    AesGcm? fallback,
    Random? random,
  })  : fallback = fallback ??
            BackgroundAesGcm(
              secretKeyLength: secretKeyLength,
              random: random,
            ),
        channelPolicy = channelPolicy ?? FlutterCipher.defaultChannelPolicy,
        super.constructor(random: random);

  /// Constructs Flutter-optimized [AesGcm] which will use 128-bit keys.
  ///
  /// The [channelPolicy] can be used to choose which requests are sent to the
  /// plugin implementation (using a Flutter [MethodChannel]) and which ones are
  /// handled in the same isolate.
  /// The default [FlutterCipher.defaultChannelPolicy] forces small [encrypt] /
  /// [decrypt] calls to be handled in the same isolate.
  ///
  /// When operating system APIs are not available [fallback] is used. The
  /// default fallback implementation is [BackgroundAesGcm].
  ///
  /// If you want deterministic key generation for testing, you can pass a
  /// [Random] instance that returns the same sequence of bytes every time.
  FlutterAesGcm.with128bits({
    CryptographyChannelPolicy? channelPolicy,
    Random? random,
  }) : this(
          secretKeyLength: 16,
          channelPolicy: channelPolicy,
          random: random,
        );

  /// Constructs Flutter-optimized [AesGcm] which will use 192-bit keys.
  ///
  /// The [channelPolicy] can be used to choose which requests are sent to the
  /// plugin implementation (using a Flutter [MethodChannel]) and which ones are
  /// handled in the same isolate.
  /// The default [FlutterCipher.defaultChannelPolicy] forces small [encrypt] /
  /// [decrypt] calls to be handled in the same isolate.
  ///
  /// When operating system APIs are not available [fallback] is used. The
  /// default fallback implementation is [BackgroundAesGcm].
  ///
  /// If you want deterministic key generation for testing, you can pass a
  /// [Random] instance that returns the same sequence of bytes every time.
  FlutterAesGcm.with192bits({
    CryptographyChannelPolicy? channelPolicy,
    Random? random,
  }) : this(
          secretKeyLength: 24,
          channelPolicy: channelPolicy,
          random: random,
        );

  /// Constructs Flutter-optimized [AesGcm] which will use 256-bit keys.
  ///
  /// The [channelPolicy] can be used to choose which requests are sent to the
  /// plugin implementation (using a Flutter [MethodChannel]) and which ones are
  /// handled in the same isolate.
  /// The default [FlutterCipher.defaultChannelPolicy] forces small [encrypt] /
  /// [decrypt] calls to be handled in the same isolate.
  ///
  /// When operating system APIs are not available [fallback] is used. The
  /// default fallback implementation is [BackgroundAesGcm].
  ///
  /// If you want deterministic key generation for testing, you can pass a
  /// [Random] instance that returns the same sequence of bytes every time.
  FlutterAesGcm.with256bits({
    CryptographyChannelPolicy? channelPolicy,
    Random? random,
  }) : this(
          secretKeyLength: 32,
          channelPolicy: channelPolicy,
          random: random,
        );

  @override
  String get channelCipherName => 'AES_GCM';

  // TODO:
  // Enable Android when we the following issues are fixed:
  //   * The Android implementation is slow.
  //   * The Android implementation returns truncated outputs sometimes when
  //     key size 192 bits. Why?
  @override
  bool get isSupportedPlatform =>
      FlutterCryptography.isPluginPresent &&
      ((isAndroid && secretKeyLength != 24) || isCupertino);

  @override
  int get nonceLength => AesGcm.defaultNonceLength;
}
