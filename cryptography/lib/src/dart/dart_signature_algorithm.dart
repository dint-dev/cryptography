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

import '../../cryptography_plus.dart';

/// A mixin for pure Dart implementations of [SignatureAlgorithm].
mixin DartSignatureAlgorithmMixin implements SignatureAlgorithm {
  @override
  Future<Signature> sign(
    List<int> input, {
    required KeyPair keyPair,
  }) async {
    final keyPairData = await keyPair.extract();
    return signSync(
      input,
      keyPairData: keyPairData,
    );
  }

  /// Signs a message synchronously (unlike [sign]).
  Signature signSync(
    List<int> input, {
    required KeyPairData keyPairData,
  });

  @override
  Future<bool> verify(
    List<int> input, {
    required Signature signature,
  }) async {
    return verifySync(input, signature: signature);
  }

  /// Verifies a signature synchronously (unlike [verify]).
  bool verifySync(
    List<int> input, {
    required Signature signature,
  });
}
