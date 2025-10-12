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

import 'dart:collection';
import 'dart:typed_data';

import 'package:cryptography_plus/cryptography_plus.dart';

/// List of security-sensitive bytes that can be destroyed with [destroy].
///
/// After destroying bytes, any attempt to read them will cause [StateError].
///
/// This class is internally used by [SecretKeyData] and various [KeyPairData]
/// classes to enhance protection of secrets in memory.
class SensitiveBytes extends ListBase<int> {
  List<int>? _bytes;

  /// Whether bytes will be overwritten with zeros when [destroy] is called.
  final bool overwriteWhenDestroyed;

  SensitiveBytes(this._bytes, {this.overwriteWhenDestroyed = false});

  /// Whether [destroy] has been called.
  bool get hasBeenDestroyed => _bytes == null;

  @override
  int get length {
    final bytes = _bytes;
    if (bytes == null) {
      throw UnsupportedError('The bytes have been destroyed');
    }
    return bytes.length;
  }

  @override
  set length(int newLength) {
    throw UnsupportedError('The bytes are unmodifiable.');
  }

  @override
  int operator [](int index) {
    final bytes = _bytes;
    if (bytes == null) {
      throw StateError('The bytes have been destroyed');
    }
    return bytes[index];
  }

  @override
  void operator []=(int index, int value) {
    throw UnsupportedError('The bytes are unmodifiable.');
  }

  /// Destroys the bytes.
  ///
  /// The method overwrites the bytes with zeroes unless overwriting causes
  /// [UnsupportedError]. Finally the reference to the list is discarded,
  /// freeing it for garbage collection.
  ///
  /// After destroying bytes, any attempt to read them will cause [StateError].
  void destroy() {
    final bytes = _bytes;
    if (bytes != null) {
      _bytes = null;
      if (overwriteWhenDestroyed) {
        try {
          for (var i = 0; i < bytes.length; i++) {
            bytes[i] = 0;
          }
        } on UnsupportedError {
          // Ignore error
        } on StateError {
          // Ignore error
        }
      }
    }
  }

  @override
  List<int> toList({bool growable = true}) {
    final bytes = _bytes;
    if (bytes == null) {
      throw UnsupportedError('The bytes have been destroyed');
    }
    if (growable) {
      return List<int>.from(bytes, growable: true);
    }
    return Uint8List.fromList(bytes);
  }
}
