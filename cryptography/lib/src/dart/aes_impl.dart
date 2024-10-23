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

import 'dart:typed_data';

import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:cryptography_plus/helpers.dart';

import '../../dart.dart';
import 'aes_impl_constants.dart' as constants;

const _numberOfRounds = {
  16: 10,
  24: 12,
  32: 14,
};

Uint32List aesBlocksFromBytes(List<int> bytes) {
  final result = Uint32List((bytes.length + 15) ~/ 16 * 4);
  final resultBytes = Uint8List.view(result.buffer);
  resultBytes.setAll(0, bytes);
  return result;
}

void aesDecryptBlock(
  Uint32List result,
  int resultStart,
  Uint32List clearText,
  int clearTextStart,
  Uint32List key,
) {
  // Read input
  var v0 = clearText[clearTextStart];
  var v1 = clearText[clearTextStart + 1];
  var v2 = clearText[clearTextStart + 2];
  var v3 = clearText[clearTextStart + 3];
  if (Endian.host == Endian.little) {
    v0 = _uint32ChangeEndian(v0);
    v1 = _uint32ChangeEndian(v1);
    v2 = _uint32ChangeEndian(v2);
    v3 = _uint32ChangeEndian(v3);
  }

  // The first round
  v0 ^= key[0];
  v1 ^= key[1];
  v2 ^= key[2];
  v3 ^= key[3];

  // Rounds 1..N-1
  const c0 = constants.d0;
  const c1 = constants.d1;
  const c2 = constants.d2;
  const c3 = constants.d3;
  var keyIndex = 4;
  final rounds = key.length ~/ 4 - 1;
  for (var round = 1; round < rounds; round++) {
    final t0 = c0[0xFF & (v0 >> 24)] ^
        c1[0xFF & (v3 >> 16)] ^
        c2[0xFF & (v2 >> 8)] ^
        c3[0xFF & v1];
    final t1 = c0[0xFF & (v1 >> 24)] ^
        c1[0xFF & (v0 >> 16)] ^
        c2[0xFF & (v3 >> 8)] ^
        c3[0xFF & (v2 >> 0)];
    final t2 = c0[0xFF & (v2 >> 24)] ^
        c1[0xFF & (v1 >> 16)] ^
        c2[0xFF & (v0 >> 8)] ^
        c3[0xFF & (v3 >> 0)];
    final t3 = c0[0xFF & (v3 >> 24)] ^
        c1[0xFF & (v2 >> 16)] ^
        c2[0xFF & (v1 >> 8)] ^
        c3[0xFF & (v0 >> 0)];
    v0 = t0 ^ key[keyIndex + 0];
    v1 = t1 ^ key[keyIndex + 1];
    v2 = t2 ^ key[keyIndex + 2];
    v3 = t3 ^ key[keyIndex + 3];
    keyIndex += 4;
  }

  // The last round with S-box constant or S-box inverse constant.
  const sInv = constants.sInv;
  var r0 = ((0xFF & sInv[0xFF & (v0 >> 24)]) << 24) |
      ((0xFF & sInv[0xFF & (v3 >> 16)]) << 16) |
      ((0xFF & sInv[0xFF & (v2 >> 8)]) << 8) |
      (0xFF & sInv[0xFF & v1]);
  var r1 = ((0xFF & sInv[0xFF & (v1 >> 24)]) << 24) |
      ((0xFF & sInv[0xFF & (v0 >> 16)]) << 16) |
      ((0xFF & sInv[0xFF & (v3 >> 8)]) << 8) |
      (0xFF & sInv[0xFF & v2]);
  var r2 = ((0xFF & sInv[0xFF & (v2 >> 24)]) << 24) |
      ((0xFF & sInv[0xFF & (v1 >> 16)]) << 16) |
      ((0xFF & sInv[0xFF & (v0 >> 8)]) << 8) |
      (0xFF & sInv[0xFF & v3]);
  var r3 = ((0xFF & sInv[0xFF & (v3 >> 24)]) << 24) |
      ((0xFF & sInv[0xFF & (v2 >> 16)]) << 16) |
      ((0xFF & sInv[0xFF & (v1 >> 8)]) << 8) |
      (0xFF & sInv[0xFF & v0]);
  r0 ^= key[keyIndex + 0];
  r1 ^= key[keyIndex + 1];
  r2 ^= key[keyIndex + 2];
  r3 ^= key[keyIndex + 3];

  // Write output
  if (Endian.host == Endian.little) {
    r0 = _uint32ChangeEndian(r0);
    r1 = _uint32ChangeEndian(r1);
    r2 = _uint32ChangeEndian(r2);
    r3 = _uint32ChangeEndian(r3);
  }
  result[resultStart] = r0;
  result[resultStart + 1] = r1;
  result[resultStart + 2] = r2;
  result[resultStart + 3] = r3;
}

void aesEncryptBlock(
  Uint32List result,
  int resultStart,
  Uint32List clearText,
  int clearTextStart,
  Uint32List key,
) {
  // Read input
  var v0 = clearText[clearTextStart];
  var v1 = clearText[clearTextStart + 1];
  var v2 = clearText[clearTextStart + 2];
  var v3 = clearText[clearTextStart + 3];
  if (Endian.host == Endian.little) {
    v0 = _uint32ChangeEndian(v0);
    v1 = _uint32ChangeEndian(v1);
    v2 = _uint32ChangeEndian(v2);
    v3 = _uint32ChangeEndian(v3);
  }

  // The first round
  v0 ^= key[0];
  v1 ^= key[1];
  v2 ^= key[2];
  v3 ^= key[3];

  // Rounds 1..N-1
  final c0 = constants.e0;
  final c1 = constants.e1;
  final c2 = constants.e2;
  final c3 = constants.e3;
  var keyIndex = 4;
  final rounds = key.length ~/ 4 - 1;
  for (var round = 1; round < rounds; round++) {
    final t0 = c0[0xFF & (v0 >> 24)] ^
        c1[0xFF & (v1 >> 16)] ^
        c2[0xFF & (v2 >> 8)] ^
        c3[0xFF & v3] ^
        key[keyIndex + 0];
    final t1 = c0[0xFF & (v1 >> 24)] ^
        c1[0xFF & (v2 >> 16)] ^
        c2[0xFF & (v3 >> 8)] ^
        c3[0xFF & (v0 >> 0)] ^
        key[keyIndex + 1];
    final t2 = c0[0xFF & (v2 >> 24)] ^
        c1[0xFF & (v3 >> 16)] ^
        c2[0xFF & (v0 >> 8)] ^
        c3[0xFF & (v1 >> 0)] ^
        key[keyIndex + 2];
    final t3 = c0[0xFF & (v3 >> 24)] ^
        c1[0xFF & (v0 >> 16)] ^
        c2[0xFF & (v1 >> 8)] ^
        c3[0xFF & (v2 >> 0)] ^
        key[keyIndex + 3];
    v0 = t0;
    v1 = t1;
    v2 = t2;
    v3 = t3;
    keyIndex += 4;
  }

  // The last round with S-box constant or S-box inverse constant.
  const s = constants.s;
  var r0 = ((0xFF & s[0xFF & (v0 >> 24)]) << 24) |
      ((0xFF & s[0xFF & (v1 >> 16)]) << 16) |
      ((0xFF & s[0xFF & (v2 >> 8)]) << 8) |
      (0xFF & s[0xFF & v3]);
  var r1 = ((0xFF & s[0xFF & (v1 >> 24)]) << 24) |
      ((0xFF & s[0xFF & (v2 >> 16)]) << 16) |
      ((0xFF & s[0xFF & (v3 >> 8)]) << 8) |
      (0xFF & s[0xFF & v0]);
  var r2 = ((0xFF & s[0xFF & (v2 >> 24)]) << 24) |
      ((0xFF & s[0xFF & (v3 >> 16)]) << 16) |
      ((0xFF & s[0xFF & (v0 >> 8)]) << 8) |
      (0xFF & s[0xFF & v1]);
  var r3 = ((0xFF & s[0xFF & (v3 >> 24)]) << 24) |
      ((0xFF & s[0xFF & (v0 >> 16)]) << 16) |
      ((0xFF & s[0xFF & (v1 >> 8)]) << 8) |
      (0xFF & s[0xFF & v2]);
  r0 ^= key[keyIndex + 0];
  r1 ^= key[keyIndex + 1];
  r2 ^= key[keyIndex + 2];
  r3 ^= key[keyIndex + 3];

  // Write output
  if (Endian.host == Endian.little) {
    r0 = _uint32ChangeEndian(r0);
    r1 = _uint32ChangeEndian(r1);
    r2 = _uint32ChangeEndian(r2);
    r3 = _uint32ChangeEndian(r3);
  }
  result[resultStart] = r0;
  result[resultStart + 1] = r1;
  result[resultStart + 2] = r2;
  result[resultStart + 3] = r3;
}

Uint32List aesExpandKeyForDecrypting(SecretKeyData secretKeyData) {
  if (secretKeyData is _DartAesSecretKeyData) {
    final existing = secretKeyData._expandedBytesForDecrypting;
    if (existing != null) {
      return existing;
    }
  }
  // Construct
  final encryptingKey = aesExpandKeyForEncrypting(secretKeyData);
  final result = Uint32List(encryptingKey.length);
  const d0 = constants.d0;
  const d1 = constants.d1;
  const d2 = constants.d2;
  const d3 = constants.d3;
  final s = constants.s;
  for (var i = 0; i < result.length; i += 4) {
    final encryptionKeyIndex = result.length - i - 4;
    for (var j = 0; j < 4; j++) {
      var value = encryptingKey[encryptionKeyIndex + j];
      if (i > 0 && i < result.length - 4) {
        value = d0[s[value >> 24]] ^
            d1[s[0xFF & (value >> 16)]] ^
            d2[s[0xFF & (value >> 8)]] ^
            d3[s[0xFF & value]];
      }
      result[i + j] = value;
    }
  }
  if (secretKeyData is _DartAesSecretKeyData) {
    secretKeyData._expandedBytesForDecrypting = result;
  }
  return result;
}

/// Pre-processes the AES key for encrypting.
Uint32List aesExpandKeyForEncrypting(SecretKeyData secretKeyData) {
  if (secretKeyData is _DartAesSecretKeyData) {
    final existing = secretKeyData._expandedBytesForEncrypting;
    if (existing != null) {
      return existing;
    }
  }

  final key = secretKeyData.bytes;

  // Number of rounds
  final rounds = _numberOfRounds[key.length];
  if (rounds == null) {
    throw ArgumentError('Invalid key length');
  }

  // Construct
  final result = Uint32List((rounds + 1) * 4);
  final resultByteData = ByteData.view(
    result.buffer,
    result.offsetInBytes,
    key.length,
  );
  for (var i = 0; i < key.length; i++) {
    resultByteData.setUint8(i, key[i]);
  }

  // Change endian
  final n = key.length ~/ 4;
  if (Endian.host == Endian.little) {
    for (var i = 0; i < n; i++) {
      result[i] = resultByteData.getUint32(4 * i, Endian.big);
    }
  }

  for (var i = n; i < result.length; i++) {
    var value = result[i - 1];
    if (i % n == 0) {
      // We mask with 0xFFFFFFFF to ensure the compiler recognizes the value will
      // be small enough to be a 'mint'.
      value = _subW((0xFFFFFFFF & (value << 8)) | (value >> 24));
      value ^= (0xFFFFFFFF & (constants.rcon[i ~/ n - 1] << 24));
    } else if (n > 6 && i % n == 4) {
      value = _subW(value);
    }
    result[i] = value ^ result[i - n];
  }

  if (secretKeyData is _DartAesSecretKeyData) {
    secretKeyData._expandedBytesForEncrypting = result;
  }

  return result;
}

/// Used for expanding decryption key.
int _subW(int w) {
  final s = constants.s;
  return (0xFFFFFFFF & (s[0xFF & (w >> 24)]) << 24) |
      (0xFFFFFFFF & (s[0xFF & (w >> 16)]) << 16) |
      (0xFFFFFFFF & (s[0xFF & (w >> 8)]) << 8) |
      (0xFFFFFFFF & (s[0xFF & w]));
}

int _uint32ChangeEndian(int v) {
  // We mask with 0xFFFFFFFF to ensure the compiler recognizes the value will
  // be small enough to be a 'mint'.
  return (0xFFFFFFFF & ((0xFF & v) << 24)) |
      (0xFFFFFF & ((0xFF & (v >> 8)) << 16)) |
      (0xFFFF & ((0xFF & (v >> 16)) << 8)) |
      (0xFF & (v >> 24));
}

mixin DartAesMixin implements DartCipher {
  @override
  Future<SecretKey> newSecretKey() {
    final bytes = Uint8List(secretKeyLength);
    fillBytesWithSecureRandom(bytes, random: random);
    return Future<_DartAesSecretKeyData>.value(_DartAesSecretKeyData(
      bytes,
      overwriteWhenDestroyed: true,
    ));
  }

  @override
  Future<SecretKey> newSecretKeyFromBytes(List<int> bytes) {
    if (bytes.length != secretKeyLength) {
      throw ArgumentError('Invalid secret key length');
    }
    return Future<_DartAesSecretKeyData>.value(
      _DartAesSecretKeyData(bytes),
    );
  }
}

class _DartAesSecretKeyData extends SecretKeyData {
  Uint32List? _expandedBytesForEncrypting;
  Uint32List? _expandedBytesForDecrypting;

  _DartAesSecretKeyData(
    List<int> bytes, {
    bool overwriteWhenDestroyed = false,
  }) : super(bytes, overwriteWhenDestroyed: overwriteWhenDestroyed);

  @override
  void destroy() {
    super.destroy();
    _erase(_expandedBytesForEncrypting);
    _erase(_expandedBytesForDecrypting);
    _expandedBytesForEncrypting = null;
    _expandedBytesForDecrypting = null;
  }

  static void _erase(Uint32List? list) {
    if (list != null) {
      list.fillRange(0, list.length, 0);
    }
  }
}
