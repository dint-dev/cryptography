import 'dart:io';

import 'package:cryptography/cryptography.dart';

import 'cipher.dart';

/// [AesCbc] implemented with operating system APIs.
class FlutterAesCbc extends FlutterCipher implements AesCbc {
  @override
  final AesCbc fallback;

  @override
  FlutterAesCbc(this.fallback);

  @override
  bool get isSupportedPlatform => Platform.isAndroid;

  @override
  String get pluginCipherName => 'AesCbc';

  @override
  int get secretKeyLength => fallback.secretKeyLength;
}
