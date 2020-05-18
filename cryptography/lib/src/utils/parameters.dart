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

import 'package:cryptography/cryptography.dart';
import 'package:meta/meta.dart';

/// Checks that cipher parameters are valid and throws a descriptive error
/// message when something is wrong.
void checkCipherParameters(
  Cipher cipher, {
  @required int secretKeyLength,
  @required Nonce nonce,
  @required bool aad,
  @required int keyStreamIndex,
  int keyStreamFactor,
}) {
  if (secretKeyLength != null &&
      !cipher.secretKeyValidLengths.contains(secretKeyLength)) {
    throw ArgumentError('Secret key length is invalid: $secretKeyLength');
  }
  final minNonceLength = cipher.nonceLengthMin;
  if (minNonceLength != null) {
    ArgumentError.checkNotNull(nonce, 'nonce');
    final nonceLength = nonce.bytes.length;
    if (nonceLength < minNonceLength || nonceLength > cipher.nonceLengthMax) {
      throw ArgumentError('Nonce length is invalid: $nonceLength');
    }
  }
  if (aad && !cipher.supportsAad) {
    throw ArgumentError('AAD must be null');
  }
  ArgumentError.checkNotNull(keyStreamIndex, 'keyStreamIndex');
  if (keyStreamIndex != 0) {
    if (keyStreamFactor == null) {
      throw ArgumentError.value(
        keyStreamIndex,
        'keyStreamIndex',
        'Must be 0',
      );
    }
    if (keyStreamFactor != 1 && keyStreamIndex % keyStreamFactor != 0) {
      throw ArgumentError.value(
        keyStreamIndex,
        'keyStreamIndex',
        'Must be a multiple of $keyStreamFactor',
      );
    }
  }
}
