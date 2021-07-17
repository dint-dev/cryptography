import 'dart:io';

import 'package:cryptography/cryptography.dart';

import 'cipher.dart';

/// [AesCtr] implemented with operating system APIs.
class FlutterAesCtr extends FlutterStreamingCipher implements AesCtr {
  @override
  final AesCtr fallback;

  FlutterAesCtr(this.fallback);

  @override
  int get counterBits => fallback.counterBits;

  @override
  bool get isSupportedPlatform => Platform.isAndroid;

  @override
  String get pluginCipherName => 'AesCtr';

  @override
  int get secretKeyLength => fallback.secretKeyLength;
}
