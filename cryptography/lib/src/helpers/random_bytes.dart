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

import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography_plus/helpers.dart';

import '../../cryptography_plus.dart';

export 'random_bytes_impl_default.dart'
    if (dart.library.html) 'random_bytes_impl_browser.dart';

const _hexChars = [
  '0',
  '1',
  '2',
  '3',
  '4',
  '5',
  '6',
  '7',
  '8',
  '9',
  'a',
  'b',
  'c',
  'd',
  'e',
  'f'
];

/// Generates a list of [length] random bytes.
///
/// By default, cryptographically secure [SecureRandom.fast] is used.
Uint8List randomBytes(int length, {Random? random}) {
  final bytes = Uint8List(length);
  fillBytesWithSecureRandom(bytes, random: random);
  return bytes;
}

/// Generates a hex string of [length] random bytes.
///
/// By default, cryptographically secure [SecureRandom.fast] is used.
String randomBytesAsHexString(int length, {Random? random}) {
  final sb = StringBuffer();
  random ??= SecureRandom.safe;
  for (var i = 0; i < length; i++) {
    final x = random.nextInt(256);
    sb.write(_hexChars[x >> 4]);
    sb.write(_hexChars[0xF & x]);
  }
  return sb.toString();
}
