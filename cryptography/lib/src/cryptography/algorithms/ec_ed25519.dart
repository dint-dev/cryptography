// Copyright 2019 Gohilla Ltd (https://gohilla.com).
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

import 'package:cryptography/cryptography.dart';

/// _Ed25519_ ([RFC 8032](https://tools.ietf.org/html/rfc8032)) signature
/// algorithm.
///
/// An example:
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   final algorithm = ed25519;
///   final keyPair = algorithm.newKeyPair();
///   final signature = await algorithm.sign([1,2,3], keyPair);
///
///   // Anyone can verify the signature
///   final isVerified = await algorithm.verify([1,2,3], signature);
/// }
/// ```
const SignatureAlgorithm ed25519 = _Ed25519();

class _Ed25519 extends SignatureAlgorithm {
  @override
  KeyPairGenerator get keyPairGenerator => const _Ed25519KeyPairGenerator();

  const _Ed25519();

  @override
  String get name => 'ed25519';

  @override
  bool verifySync(List<int> input, Signature signature) {
    throw UnimplementedError();
  }

  @override
  Signature signSync(List<int> input, KeyPair keyPair) {
    throw UnimplementedError();
  }
}

class _Ed25519KeyPairGenerator extends KeyPairGenerator {
  @override
  String get name => 'ed25519';

  const _Ed25519KeyPairGenerator();

  @override
  KeyPair generateSync() {
    // TODO: implement generateSync
    return null;
  }
}
