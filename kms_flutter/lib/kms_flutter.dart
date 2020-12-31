// Copyright 2019-2020 Gohilla Ltd.
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

/// Contains a [Kms] implementation for Flutter applications.
///
/// Works in:
///   * Browsers
///   * Android
///   * iOS
///   * Mac OS X
///
/// ```
/// import 'package:kms_flutter/kms_flutter.dart'
///
/// void main() {
///   // In browsers, returns BrowserKms.
///   // In other platforms, returns PluginKms.
///   final kms = flutterKms();
///
///   // Create a key pair.
///   final keyPairDocument = await kms.collection('example').createKeyPair(
///     keyExchangeType: null,
///     signatureType: SignatureType.ed25519,
///     keyDocumentSecurity: KeyDocumentSecurity.highest,
///   );
///
///   // Sign a message
///   final signature = await keyPairDocument.sign([1, 2, 3]);
///   print('Public key: ${signature.publicKey}');
///   print('Signature: $signature');
///
///   // ...
///
///   // Delete
///   await keyPairDocument.delete();
/// }
/// ```
library kms_flutter;

import 'package:cryptography/cryptography.dart';
import 'package:kms/kms.dart';

class FlutterKms extends Kms {
  static void enable() {
    final kms = FlutterKms();
    Cryptography.instance = KmsCryptography(kms, Cryptography.instance);
  }
}