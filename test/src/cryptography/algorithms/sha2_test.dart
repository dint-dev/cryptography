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
import 'package:cryptography/utils.dart';
import 'package:test/test.dart';

void main() {
  group('sha224:', () {
    test('hash length is correct', () {
      expect(sha224.hashLengthInBytes, 28);
    });
    test('test vector works', () async {
      final expectedBytes = hexToBytes(
        'd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f',
      );
      final hash = await sha224.hash(const <int>[]);
      expect(
        hexFromBytes(hash.bytes),
        hexFromBytes(expectedBytes),
      );
    });
  });

  group('sha256:', () {
    test('hash length is correct', () {
      expect(sha256.hashLengthInBytes, 32);
    });
    test('test vector works', () async {
      final expectedBytes = hexToBytes(
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      );
      final hash = await sha256.hash(const <int>[]);
      expect(
        hexFromBytes(hash.bytes),
        hexFromBytes(expectedBytes),
      );
    });
  });

  group('sha384:', () {
    test('hash length is correct', () {
      expect(sha384.hashLengthInBytes, 48);
    });
    test('test vector works', () async {
      final expectedBytes = hexToBytes(
        '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b',
      );
      final hash = await sha384.hash(const <int>[]);
      expect(
        hexFromBytes(hash.bytes),
        hexFromBytes(expectedBytes),
      );
    });
  });

  group('sha512:', () {
    test('hash length is correct', () {
      expect(sha512.hashLengthInBytes, 64);
    });
    test('test vector works', () async {
      final expectedBytes = hexToBytes(
        'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e',
      );
      final hash = await sha512.hash(const <int>[]);
      expect(
        hexFromBytes(hash.bytes),
        hexFromBytes(expectedBytes),
      );
    });
  });
}
