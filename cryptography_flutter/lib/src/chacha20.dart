import 'dart:io';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart';

import 'cipher.dart';

/// [Chacha20] implemented with operating system APIs.
class FlutterChacha20 extends FlutterStreamingCipher implements Chacha20 {
  @override
  final Chacha20 fallback;

  FlutterChacha20(this.fallback);

  @override
  bool get isSupportedPlatform =>
      (Platform.isAndroid || Platform.isIOS || Platform.isMacOS) &&
      macAlgorithm is DartChacha20Poly1305AeadMacAlgorithm;

  @override
  String get pluginCipherName => 'Chacha20.poly1305Aead';
}
