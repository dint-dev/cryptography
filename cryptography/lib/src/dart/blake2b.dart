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
import 'package:cryptography_plus/dart.dart';

import 'blake2b_impl_vm.dart'
    if (dart.library.html) 'blake2b_impl_browser.dart';

/// [Blake2b] implemented in pure Dart.
///
/// For examples and more information about the algorithm, see documentation for
/// the class [Blake2b].
class DartBlake2b extends Blake2b
    with DartHashAlgorithmMixin, DartMacAlgorithmMixin {
  const DartBlake2b({
    super.hashLengthInBytes = Blake2b.defaultHashLengthInBytes,
  }) : super.constructor();

  @override
  DartBlake2b toSync() {
    return this;
  }

  @override
  DartBlake2b replace({int? hashLength}) {
    hashLength ??= hashLengthInBytes;
    if (hashLength == hashLengthInBytes) {
      return this;
    }
    return DartBlake2b(
      hashLengthInBytes: hashLength,
    );
  }

  @override
  Blake2bSink newMacSinkSync({
    required SecretKeyData secretKeyData,
    List<int> nonce = const <int>[],
    List<int> aad = const <int>[],
  }) {
    return Blake2bSink(
      hashLengthInBytes: hashLengthInBytes,
    )..initializeSync(
        secretKey: secretKeyData,
        nonce: nonce,
        aad: aad,
      );
  }

  @override
  Blake2bSink newHashSink() {
    return Blake2bSink(
      hashLengthInBytes: hashLengthInBytes,
    );
  }
}
