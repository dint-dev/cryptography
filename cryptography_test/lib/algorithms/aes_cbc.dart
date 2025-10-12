// Copyright 2023 Gohilla.
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
import 'package:test/test.dart';

import '../cipher.dart';

void testAesCbc() {
  testCipher<AesCbc>(
    builder: () => AesCbc.with128bits(
      macAlgorithm: MacAlgorithm.empty,
    ),
    onEquality: (a, b) {
      expect(a.paddingAlgorithm, b.paddingAlgorithm);
    },
  );
  testCipher<AesCbc>(
    builder: () => AesCbc.with128bits(
      macAlgorithm: MacAlgorithm.empty,
      paddingAlgorithm: PaddingAlgorithm.zero,
    ),
    onEquality: (a, b) {
      expect(a.paddingAlgorithm, b.paddingAlgorithm);
    },
  );
  testCipher(
    builder: () => AesCbc.with128bits(
      macAlgorithm: Hmac.sha256(),
    ),
  );
  testCipher(
    builder: () => AesCbc.with192bits(
      macAlgorithm: MacAlgorithm.empty,
    ),
  );
  testCipher(
    builder: () => AesCbc.with256bits(
      macAlgorithm: MacAlgorithm.empty,
    ),
  );
  testCipher(
    builder: () => AesCbc.with256bits(
      macAlgorithm: Hmac.sha256(),
    ),
  );
  testCipher(
    builder: () => AesCbc.with256bits(
      macAlgorithm: Hmac.sha512(),
    ),
  );
}
