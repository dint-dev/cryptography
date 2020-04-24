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

library aes;

import 'dart:typed_data';

part 'aes_impl_constants.dart';

const _numberOfRounds = {
  16: 10,
  24: 12,
  32: 14,
};

Uint32List prepareEncrypt(List<int> key) {
  final rounds = _numberOfRounds[key.length];
  if (rounds == null) {
    throw ArgumentError('Invalid key length');
  }
  final encryptionData = Uint32List((rounds + 1) * 4);
  var roundKeyCount = (rounds + 1) * 4;
  var keyLengthInWords = key.length ~/ 4;
  var words = _uint32ListFrom(key, 0, key.length);

  for (var i = 0; i < keyLengthInWords; i++) {
    encryptionData[i] = words[i];
  }

  var roundConstantIndex = 0;
  for (var t = keyLengthInWords; t < roundKeyCount;) {
    var word = words[keyLengthInWords - 1];

    words[0] ^= ((_S[(word >> 16) & 0xFF] << 24) ^
        (_S[(word >> 8) & 0xFF] << 16) ^
        (_S[word & 0xFF] << 8) ^
        _S[(word >> 24) & 0xFF] ^
        (_roundConstants[roundConstantIndex] << 24));

    roundConstantIndex++;

    if (keyLengthInWords != 8) {
      for (var i = 1; i < keyLengthInWords; i++) {
        words[i] ^= words[i - 1];
      }
    } else {
      for (var i = 1; i < (keyLengthInWords ~/ 2); i++) {
        words[i] ^= words[i - 1];
      }
      word = words[(keyLengthInWords ~/ 2) - 1];

      words[keyLengthInWords ~/ 2] ^= (_S[0xFF & word] ^
          (_S[0xFF & (word >> 8)] << 8) ^
          (_S[0xFF & (word >> 16)] << 16) ^
          (_S[0xFF & (word >> 24)] << 24));

      for (var i = (keyLengthInWords ~/ 2) + 1; i < keyLengthInWords; i++) {
        words[i] ^= words[i - 1];
      }
    }
    for (var i = 0; i < keyLengthInWords && t < roundKeyCount; i++) {
      encryptionData[t] = words[i];
      t++;
    }
  }
  return encryptionData;
}

Uint32List prepareDecrypt(List<int> key) {
  final rounds = _numberOfRounds[key.length];
  if (rounds == null) {
    throw ArgumentError('Invalid key length');
  }
  final decryptionData = Uint32List((rounds + 1) * 4);
  var roundKeyCount = (rounds + 1) * 4;
  var keyLengthInWords = key.length ~/ 4;
  var words = _uint32ListFrom(key, 0, key.length);

  for (var i = 0; i < keyLengthInWords; i++) {
    final word = words[i];
    decryptionData[4 * (rounds - (i ~/ 4)) + i % 4] = word;
  }

  var roundConstantIndex = 0;
  for (var t = keyLengthInWords; t < roundKeyCount;) {
    var word = words[keyLengthInWords - 1];

    words[0] ^= ((_S[(word >> 16) & 0xFF] << 24) ^
        (_S[(word >> 8) & 0xFF] << 16) ^
        (_S[word & 0xFF] << 8) ^
        _S[(word >> 24) & 0xFF] ^
        (_roundConstants[roundConstantIndex] << 24));

    roundConstantIndex++;

    if (keyLengthInWords != 8) {
      for (var i = 1; i < keyLengthInWords; i++) {
        words[i] ^= words[i - 1];
      }
    } else {
      for (var i = 1; i < (keyLengthInWords ~/ 2); i++) {
        words[i] ^= words[i - 1];
      }
      word = words[(keyLengthInWords ~/ 2) - 1];

      words[keyLengthInWords ~/ 2] ^= (_S[0xFF & word] ^
          (_S[0xFF & (word >> 8)] << 8) ^
          (_S[0xFF & (word >> 16)] << 16) ^
          (_S[0xFF & (word >> 24)] << 24));

      for (var i = (keyLengthInWords ~/ 2) + 1; i < keyLengthInWords; i++) {
        words[i] ^= words[i - 1];
      }
    }
    for (var i = 0; i < keyLengthInWords && t < roundKeyCount; i++) {
      decryptionData[4 * (rounds - (t ~/ 4)) + (t % 4)] = words[i];
      t++;
    }
  }

  for (var round = 1; round < rounds; round++) {
    for (var c = 0; c < 4; c++) {
      final x = decryptionData[4 * round + c];
      decryptionData[4 * round + c] = (_U1[0xFF & (x >> 24)] ^
          _U2[0xFF & (x >> 16)] ^
          _U3[0xFF & (x >> 8)] ^
          _U4[0xFF & x]);
    }
  }
  return decryptionData;
}

void aesDecryptBlock(
  List<int> result,
  int resultStart,
  List<int> cipherText,
  int cipherTextStart,
  Uint32List decryptionData,
) {
  if (resultStart == result.length) {
    return;
  }
  if (cipherText.length - cipherTextStart < 16) {
    throw ArgumentError.value(cipherTextStart, 'cipherTextStart');
  }
  final block = _uint32ListFrom(
    cipherText,
    cipherTextStart,
    cipherTextStart + 16,
  );
  for (var i = 0; i < 4; i++) {
    block[i] ^= decryptionData[i];
  }

  final rounds = (decryptionData.length ~/ 4) - 1;
  for (var round = 1; round < rounds; round++) {
    final tmp0 = _D1[0xFF & (block[0] >> 24)] ^
        _D2[0xFF & (block[3] >> 16)] ^
        _D3[0xFF & (block[2] >> 8)] ^
        _D4[0xFF & block[1]] ^
        decryptionData[4 * round];

    final tmp1 = _D1[0xFF & (block[1] >> 24)] ^
        _D2[0xFF & (block[0] >> 16)] ^
        _D3[0xFF & (block[3] >> 8)] ^
        _D4[0xFF & block[2]] ^
        decryptionData[4 * round + 1];

    final tmp2 = _D1[0xFF & (block[2] >> 24)] ^
        _D2[0xFF & (block[1] >> 16)] ^
        _D3[0xFF & (block[0] >> 8)] ^
        _D4[0xFF & block[3]] ^
        decryptionData[4 * round + 2];

    final tmp3 = _D1[0xFF & (block[3] >> 24)] ^
        _D2[0xFF & (block[2] >> 16)] ^
        _D3[0xFF & (block[1] >> 8)] ^
        _D4[0xFF & block[0]] ^
        decryptionData[4 * round + 3];

    block[0] = tmp0;
    block[1] = tmp1;
    block[2] = tmp2;
    block[3] = tmp3;
  }

  final resultLength = result.length;
  for (var i = 0; i < 4; i++) {
    final x = decryptionData[4 * rounds + i];

    result[resultStart] = 0xFF & (_Si[0xFF & (block[i] >> 24)] ^ (x >> 24));
    resultStart++;
    if (resultStart == resultLength) {
      break;
    }

    result[resultStart] =
        0xFF & (_Si[0xFF & (block[(i + 3) % 4] >> 16)] ^ (x >> 16));
    resultStart++;
    if (resultStart == resultLength) {
      break;
    }

    result[resultStart] =
        0xFF & (_Si[0xFF & (block[(i + 2) % 4] >> 8)] ^ (x >> 8));
    resultStart++;
    if (resultStart == resultLength) {
      break;
    }

    result[resultStart] = 0xFF & (_Si[0xFF & block[(i + 1) % 4]] ^ x);
    resultStart++;
    if (resultStart == resultLength) {
      break;
    }
  }
}

void aesEncryptBlock(
  List<int> result,
  int resultStart,
  List<int> plainText,
  int plainTextStart,
  Uint32List encryptionData,
) {
  if (resultStart == result.length) {
    return;
  }
  if (plainText.length - plainTextStart < 16) {
    throw ArgumentError.value(plainTextStart, 'plainTextStart');
  }

  final block = _uint32ListFrom(
    plainText,
    plainTextStart,
    plainTextStart + 16,
  );
  for (var i = 0; i < 4; i++) {
    block[i] ^= encryptionData[i];
  }

  final rounds = (encryptionData.length ~/ 4) - 1;
  for (var round = 1; round < rounds; round++) {
    final tmp0 = _E1[0xFF & (block[0] >> 24)] ^
        _E2[0xFF & (block[1] >> 16)] ^
        _E3[0xFF & (block[2] >> 8)] ^
        _E4[0xFF & block[3]] ^
        encryptionData[4 * round];

    final tmp1 = _E1[0xFF & (block[1] >> 24)] ^
        _E2[0xFF & (block[2] >> 16)] ^
        _E3[0xFF & (block[3] >> 8)] ^
        _E4[0xFF & block[0]] ^
        encryptionData[4 * round + 1];

    final tmp2 = _E1[0xFF & (block[2] >> 24)] ^
        _E2[0xFF & (block[3] >> 16)] ^
        _E3[0xFF & (block[0] >> 8)] ^
        _E4[0xFF & block[1]] ^
        encryptionData[4 * round + 2];

    final tmp3 = _E1[0xFF & (block[3] >> 24)] ^
        _E2[0xFF & (block[0] >> 16)] ^
        _E3[0xFF & (block[1] >> 8)] ^
        _E4[0xFF & block[2]] ^
        encryptionData[4 * round + 3];

    block[0] = tmp0;
    block[1] = tmp1;
    block[2] = tmp2;
    block[3] = tmp3;
  }

  final resultLength = result.length;
  for (var i = 0; i < 4; i++) {
    final x = encryptionData[4 * rounds + i];

    result[resultStart] = 0xFF & (_S[0xFF & (block[i] >> 24)] ^ (x >> 24));
    resultStart++;
    if (resultStart == resultLength) {
      break;
    }

    result[resultStart] =
        0xFF & (_S[0xFF & (block[(i + 1) % 4] >> 16)] ^ (x >> 16));
    resultStart++;
    if (resultStart == resultLength) {
      break;
    }

    result[resultStart] =
        0xFF & (_S[0xFF & (block[(i + 2) % 4] >> 8)] ^ (x >> 8));
    resultStart++;
    if (resultStart == resultLength) {
      break;
    }

    result[resultStart] = 0xFF & (_S[0xFF & block[(i + 3) % 4]] ^ x);
    resultStart++;
    if (resultStart == resultLength) {
      break;
    }
  }
}

Uint32List _uint32ListFrom(List<int> bytes, int start, int end) {
  final uint32List = Uint32List((end - start) ~/ 4);
  final byteData = ByteData.view(uint32List.buffer);
  for (var i = 0; i < byteData.lengthInBytes; i++) {
    byteData.setUint8(i, bytes[start + i]);
  }
  if (Endian.host != Endian.big) {
    for (var i = 0; i < uint32List.length; i++) {
      uint32List[i] = byteData.getUint32(4 * i, Endian.big);
    }
  }
  return uint32List;
}
