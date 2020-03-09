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

import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/utils.dart';
import 'package:test/test.dart';

void main() {
  test('hmac', () async {
    final expectedBytes = hexToBytes(
      '6a793fda3e700bf66a4f27e5315b0783b5ca1442a4a18c16c577d514d30302e6',
    );
    final hmac = Hmac(sha256);
    final input = utf8.encode('text');
    final secretKey = SecretKey(utf8.encode('secret'));
    final mac = await hmac.calculateMac(
      input,
      secretKey: secretKey,
    );
    expect(
      hexFromBytes(mac.bytes),
      hexFromBytes(expectedBytes),
    );
  });
}
