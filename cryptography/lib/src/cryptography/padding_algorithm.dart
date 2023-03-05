// Copyright 2019-2022 Gohilla.
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

/// Padding algorithm for block ciphers.
///
/// ## Available algorithms
///   * [PaddingAlgorithm.zero]
///   * [PaddingAlgorithm.pkcs7] (PKCS7 / PKCS5)
abstract class PaddingAlgorithm {
  /// Zero-padding.
  ///
  /// If the data length is a multiple of the block length, no padding is added.
  static const PaddingAlgorithm zero = _ZeroPaddingAlgorithm();

  /// PKCS7 padding ([RFC 5652](https://tools.ietf.org/html/rfc5652#section-6.3)).
  ///
  /// PKCS7 padding is a block cipher padding algorithm that adds one or more
  /// bytes to the plaintext, each of which has the value of the number of
  /// bytes added.
  ///
  /// If the data length is a multiple of the block length, a full block of
  /// padding is added.
  ///
  /// PKCS5 padding is identical to PKCS7 padding. The only difference is that
  /// PKCS5 specification requires a block length of 8 bytes.
  static const PaddingAlgorithm pkcs7 = _Pkcs7PaddingAlgorithm();

  const PaddingAlgorithm();

  /// Computes length of padding.
  ///
  /// Returns -1 if padding is invalid.
  int getBlockPadding(int blockLength, Uint8List bytes);

  /// Computes padding length.
  int paddingLength(int blockLength, int dataLength) {
    if (blockLength < 2 || blockLength > 0xFF) {
      throw ArgumentError.value(
        blockLength,
        'blockLength',
        'Must be between 2 and 255',
      );
    }
    if (dataLength < 0) {
      throw ArgumentError.value(dataLength, 'dataLength');
    }
    return blockLength - dataLength % blockLength;
  }

  /// Fills [bytes] with padding, starting at [start].
  ///
  /// Throws [ArgumentError] if:
  ///   * [blockBytes] length is less than 2.
  ///   * [paddingLength] is less than 0 or greater than the length of the block.
  void setBlockPadding(
    int blockLength,
    Uint8List bytes,
    int start,
  );
}

class _Pkcs7PaddingAlgorithm extends PaddingAlgorithm {
  const _Pkcs7PaddingAlgorithm();

  @override
  int getBlockPadding(
    int blockLength,
    Uint8List bytes,
  ) {
    if (blockLength < 2 || blockLength > 0xFF) {
      throw ArgumentError.value(
        blockLength,
        'blockLength',
        'Must be between 2 and 255',
      );
    }
    if (bytes.isEmpty || bytes.length % blockLength != 0) {
      return -1;
    }
    final paddingLength = bytes[bytes.length - 1];
    if (paddingLength < 1 || paddingLength > blockLength) {
      return -1;
    }
    // Check that all padding bytes are correct PKCS7 padding bytes.
    for (var i = 2; i < paddingLength; i++) {
      if (bytes[bytes.length - i] != paddingLength) {
        return -1;
      }
    }
    return paddingLength;
  }

  @override
  void setBlockPadding(int blockLength, Uint8List bytes, int start) {
    if (blockLength < 2 || blockLength > 0xFF) {
      throw ArgumentError.value(
        blockLength,
        'blockLength',
        'Must be between 2 and 255',
      );
    }
    if (start < 0 || start >= bytes.length) {
      throw ArgumentError.value(start, 'start');
    }
    if (bytes.isEmpty || bytes.length % blockLength != 0) {
      throw ArgumentError(
        'Bytes must be non-empty and a multiple of $blockLength.',
      );
    }
    final paddingLength = blockLength - start % blockLength;
    for (var i = bytes.length - paddingLength; i < bytes.length; i++) {
      bytes[i] = paddingLength;
    }
  }

  @override
  String toString() => 'PaddingAlgorithm.pkcs7';
}

class _ZeroPaddingAlgorithm extends PaddingAlgorithm {
  const _ZeroPaddingAlgorithm();

  @override
  int getBlockPadding(int blockLength, Uint8List bytes) {
    if (blockLength < 2) {
      throw ArgumentError.value(blockLength, 'blockLength');
    }
    return 0;
  }

  @override
  int paddingLength(int blockLength, int dataLength) {
    if (blockLength < 2) {
      throw ArgumentError.value(blockLength, 'blockLength');
    }
    final rem = dataLength % blockLength;
    if (rem == 0) {
      return 0;
    }
    return blockLength - rem;
  }

  @override
  void setBlockPadding(
    int blockLength,
    Uint8List bytes,
    int start,
  ) {
    if (blockLength < 2) {
      throw ArgumentError.value(blockLength, 'blockLength');
    }
  }

  @override
  String toString() => 'PaddingAlgorithm.zero';
}
