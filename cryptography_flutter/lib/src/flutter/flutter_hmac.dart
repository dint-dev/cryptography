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

import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:cryptography_plus/dart.dart';

import '../_flutter_cryptography_implementation.dart';
import '../_internal.dart';

/// [Hmac] that uses platform APIs in iOS and Mac OS X.
class FlutterHmac extends Hmac with PlatformCryptographicAlgorithm {
  @override
  final HashAlgorithm hashAlgorithm;

  @override
  late final Hmac fallback = DartHmac(hashAlgorithm);

  FlutterHmac(this.hashAlgorithm) : super.constructor();

  /// HMAC-SHA1.
  FlutterHmac.sha1() : this(Sha1());

  /// HMAC-SHA224.
  FlutterHmac.sha224() : this(Sha224());

  /// HMAC-SHA256.
  FlutterHmac.sha256() : this(Sha256());

  /// HMAC-SHA384.
  FlutterHmac.sha384() : this(Sha384());

  /// HMAC-SHA512.
  FlutterHmac.sha512() : this(Sha512());

  @override
  bool get isSupportedPlatform {
    return _hashNameFor(hashAlgorithm) != null;
  }

  @override
  Future<Mac> calculateMac(
    List<int> bytes, {
    required SecretKey secretKey,
    List<int> nonce = const <int>[],
    List<int> aad = const <int>[],
  }) async {
    final hashName = _hashNameFor(hashAlgorithm);
    if (hashName != null) {
      final result = await invokeMethod(
        'hmac',
        {
          'data': asUint8List(bytes),
          'hash': hashName,
          'key': asUint8List(await secretKey.extractBytes()),
        },
      );
      final macBytes = asUint8List(result['mac'] as List<int>);
      return Mac(macBytes);
    }
    return await BrowserCryptography.defaultInstance
        .hmac(hashAlgorithm)
        .calculateMac(
          bytes,
          secretKey: secretKey,
          nonce: nonce,
          aad: aad,
        );
  }

  static String? _hashNameFor(HashAlgorithm hashAlgorithm) {
    // Currently only Android supports HMAC.
    if (isAndroid) {
      if (hashAlgorithm is Sha1) {
        return 'SHA-1';
      }
      if (hashAlgorithm is Sha224) {
        return 'SHA-224';
      }
      if (hashAlgorithm is Sha256) {
        return 'SHA-256';
      }
      if (hashAlgorithm is Sha384) {
        return 'SHA-384';
      }
      if (hashAlgorithm is Sha512) {
        return 'SHA-512';
      }
    }
    return null;
  }
}
