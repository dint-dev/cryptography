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

import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:meta/meta.dart';

/// Superclass of [SignatureWand], [KeyExchangeWand], and [CipherWand].
///
/// The underlying secrets should be not extractable. Because instances of this
/// class can still operate "locks" without a visible key, it is like a
/// "magic wand".
abstract class Wand {
  bool _hasBeenDestroyed = false;

  /// Whether [destroy] has been called.
  bool get hasBeenDestroyed => _hasBeenDestroyed;

  /// Prevents this object from being used anymore and attempts to erase
  /// cryptographic keys from memory.
  ///
  /// Calling this is optional. Any wand will be destroyed automatically
  /// when it is garbage collected, but the secrets may exist in the heap
  /// for some time before the are overwritten, potentially exposing them to
  /// memory dumps.
  @mustCallSuper
  Future<void> destroy() async {
    _hasBeenDestroyed = true;
  }

  @override
  String toString() => '$runtimeType(...)';
}
