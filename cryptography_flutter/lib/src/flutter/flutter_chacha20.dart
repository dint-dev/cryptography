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

import '../../cryptography_flutter_plus.dart';
import '../_internal.dart';

/// [Chacha20] that uses platform APIs in Android, iOS, and Mac OS X.
///
/// When operating system APIs are not available [fallback] is used. The
/// default fallback implementation is [BackgroundChacha].
class FlutterChacha20 extends Chacha20 with FlutterCipherMixin {
  @override
  final Chacha20? fallback;

  @override
  final CryptographyChannelPolicy channelPolicy;

  /// Constructs Flutter-optimized [Chacha20.poly1305Aead].
  ///
  /// The [channelPolicy] can be used to choose which requests are sent to the
  /// plugin implementation (using a Flutter [MethodChannel]) and which ones are
  /// handled in the same isolate.
  /// The default [FlutterCipher.defaultChannelPolicy] forces small [encrypt] /
  /// [decrypt] calls to be handled in the same isolate.
  ///
  /// When operating system APIs are not available [fallback] is used. The
  /// default fallback implementation is [BackgroundChacha].
  ///
  /// If you want deterministic key generation for testing, you can pass a
  /// [Random] instance that returns the same sequence of bytes every time.
  FlutterChacha20.poly1305Aead({
    Chacha20? fallback,
    CryptographyChannelPolicy? channelPolicy,
    Random? random,
  })  : fallback = fallback ?? BackgroundChacha.poly1305Aead(),
        channelPolicy = channelPolicy ?? FlutterCipher.defaultChannelPolicy,
        super.constructor(random: random);

  @override
  String get channelCipherName => 'CHACHA20_POLY1305_AEAD';

  // TODO:
  // Enable Android when we the following issues are fixed:
  //   * The Android implementation is slow.
  @override
  bool get isSupportedPlatform =>
      FlutterCryptography.isPluginPresent && (isAndroid || isCupertino);

  @override
  MacAlgorithm get macAlgorithm => const DartChacha20Poly1305AeadMacAlgorithm();
}
