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

import 'dart:html' as html;
import 'dart:math';
import 'dart:typed_data';

import '../../cryptography_plus.dart';

const _bit32 = 0x10000 * 0x10000;

// Store the function so it can't be mutated by Javascript libraries.
final _webCryptoRandom = html.window.crypto!.getRandomValues;

void fillBytesWithSecureRandom(Uint8List bytes, {Random? random}) {
  if (random == null &&
      bytes.runtimeType == Uint8List &&
      BrowserCryptography.isSupported) {
    // Use Web Cryptography API directly (instead of Random.secure()).
    _webCryptoRandom(bytes);
  }
  random ??= SecureRandom.safe;
  for (var i = 0; i < bytes.length;) {
    if (i + 3 < bytes.length) {
      // Read 32 bits at a time.
      final x = random.nextInt(_bit32);
      bytes[i] = x >> 24;
      bytes[i + 1] = 0xFF & (x >> 16);
      bytes[i + 2] = 0xFF & (x >> 8);
      bytes[i + 3] = 0xFF & x;
      i += 4;
    } else {
      // Read 8 bits at a time.
      bytes[i] = random.nextInt(0x100);
      i++;
    }
  }
}
