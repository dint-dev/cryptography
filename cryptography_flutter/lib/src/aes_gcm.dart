import 'dart:io';

import 'package:cryptography/cryptography.dart';

import 'cipher.dart';

/// [AesGcm] implemented with operating system APIs.
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
