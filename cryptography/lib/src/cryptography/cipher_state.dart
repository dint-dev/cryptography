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

import 'dart:async';
import 'dart:typed_data';

import '../../cryptography_plus.dart';

/// A state of [Cipher], which helps you to encrypt or decrypt data that does
/// not fit in memory.
abstract class CipherState {
  /// The cipher used by this state.
  Cipher get cipher;

  /// MAC.
  Mac get mac;

  /// Adds [input] to the sequence of converted bytes and finishes converting
  /// all bytes.
  ///
  /// If [expectedMac] is non-null, then the method will throw
  /// [SecretBoxAuthenticationError] if the computed MAC does match.
  ///
  /// If [possibleBuffer] is non-null, the method is allowed (but not required)
  /// to write the output to it. The buffer can be the same as [input].
  /// Otherwise the method will allocate memory for the output.
  Future<List<int>> convert(
    List<int> input, {
    required Mac? expectedMac,
    Uint8List? possibleBuffer,
  });

  /// Adds [input] to the sequence of converted bytes. Returns a list of
  /// converted bytes, which may be empty or larger the input.
  ///
  /// You MUST later call [convert], which will finish converting.
  List<int> convertChunkSync(
    List<int> input, {
    Uint8List? possibleBuffer,
  });

  /// Initializes the state with the given [secretKey], [nonce], and [aad].
  Future<void> initialize({
    required bool isEncrypting,
    required SecretKey secretKey,
    required List<int> nonce,
    List<int> aad = const [],
    int keyStreamIndex = 0,
  });
}
