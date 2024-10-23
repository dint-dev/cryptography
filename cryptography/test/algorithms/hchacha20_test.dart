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
import 'package:cryptography_plus/src/utils.dart';
import 'package:test/test.dart';

void main() {
  test('HChacha20(...)', () async {
    // -----------------------------------------------------------------------
    // The following constants are from:
    // https://tools.ietf.org/html/draft-arciszewski-xchacha-03
    // -----------------------------------------------------------------------
    final secretKey = SecretKey(hexToBytes(
      '00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f',
    ));

    final nonce = hexToBytes(
      '00:00:00:09:00:00:00:4a:00:00:00:00:31:41:59:27',
    );

    final expected = hexToBytes(
      '82413b42 27b27bfe d30e4250 8a877d73 a0f9e4d5 8a74a853 c12ec413 26d3ecdc',
    );
    final hchacha20 = Cryptography.instance.hchacha20();
    final output = await hchacha20.deriveKey(
      secretKey: secretKey,
      nonce: nonce,
    );
    expect(
      hexFromBytes((await output.extract()).bytes),
      hexFromBytes(expected),
    );
  });
}
