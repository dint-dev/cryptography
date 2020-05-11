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

import 'web_crypto.dart';
import 'sha1_sha2_impl.dart';
import 'package:cryptography/cryptography.dart';

/// _SHA1_, an old cryptographic hash function that's not recommended for new
/// applications.
///
/// An example:
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// void main() {
///   // Create a sink
///   final sink = sha1.newSink();
///
///   // Add all parts
///   sink.add(<int>[1,2,3]);
///   sink.add(<int>[4,5]);
///
///   // Calculate hash
///   sink.close();
///   final hash = sink.hash;
///
///   print('Hash: ${hash.bytes}');
/// }
/// ```
const HashAlgorithm sha1 = webSha1 ?? dartSha1;

/// _SHA224_, a function in the SHA2 family of cryptographic hash functions.
/// In browser, the implementation uses [Web Cryptography API](https://www.w3.org/TR/WebCryptoAPI/).
/// In other platforms, the implementation uses [package:crypto](https://pub.dev/packages/crypto),
/// which is maintained by Google.
///
/// An example:
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// void main() {
///   // Create a sink
///   final sink = sha224.newSink();
///
///   // Add all parts
///   sink.add(<int>[1,2,3]);
///   sink.add(<int>[4,5]);
///
///   // Calculate hash
///   sink.close();
///   final hash = sink.hash;
///
///   print('Hash: ${hash.bytes}');
/// }
/// ```
const HashAlgorithm sha224 = dartSha224;

/// _SHA256_, a function in the SHA2 family of cryptographic hash functions.
/// In browser, the implementation uses [Web Cryptography API](https://www.w3.org/TR/WebCryptoAPI/).
/// In other platforms, the implementation uses [package:crypto](https://pub.dev/packages/crypto),
/// which is maintained by Google.
///
/// An example:
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// void main() {
///   // Create a sink
///   final sink = sha256.newSink();
///
///   // Add all parts
///   sink.add(<int>[1,2,3]);
///   sink.add(<int>[4,5]);
///
///   // Calculate hash
///   sink.close();
///   final hash = sink.hash;
///
///   print('Hash: ${hash.bytes}');
/// }
/// ```
const HashAlgorithm sha256 = webSha256 ?? dartSha256;

/// _SHA385_, a function in the SHA2 family of cryptographic hash functions.
/// In browser, the implementation uses [Web Cryptography API](https://www.w3.org/TR/WebCryptoAPI/).
/// In other platforms, the implementation uses [package:crypto](https://pub.dev/packages/crypto),
/// which is maintained by Google.
///
/// An example:
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// void main() {
///   // Create a sink
///   final sink = sha384.newSink();
///
///   // Add all parts
///   sink.add(<int>[1,2,3]);
///   sink.add(<int>[4,5]);
///
///   // Calculate hash
///   sink.close();
///   final hash = sink.hash;
///
///   print('Hash: ${hash.bytes}');
/// }
/// ```
const HashAlgorithm sha384 = webSha384 ?? dartSha384;

/// _SHA512_, a function in the SHA2 family of cryptographic hash functions.
/// In browser, the implementation uses [Web Cryptography API](https://www.w3.org/TR/WebCryptoAPI/).
/// In other platforms, the implementation uses [package:crypto](https://pub.dev/packages/crypto),
/// which is maintained by Google.
///
/// An example:
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// void main() {
///   // Create a sink
///   final sink = sha512.newSink();
///
///   // Add all parts
///   sink.add(<int>[1,2,3]);
///   sink.add(<int>[4,5]);
///
///   // Calculate hash
///   sink.close();
///   final hash = sink.hash;
///
///   print('Hash: ${hash.bytes}');
/// }
/// ```
const HashAlgorithm sha512 = webSha512 ?? dartSha512;
