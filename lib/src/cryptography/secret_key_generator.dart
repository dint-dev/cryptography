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
import 'package:meta/meta.dart';

/// Generates [SecretKey] instances.
class SecretKeyGenerator {
  final Set<int> validLengths;
  final int defaultLength;

  const SecretKeyGenerator({
    @required this.validLengths,
    @required this.defaultLength,
  });

  /// Generates a new [SecretKey].
  /// You can optionally define key `length` (in bytes).
  ///
  /// The default implementation just calls [generateSync].
  Future<SecretKey> generate({int length}) async {
    return Future<SecretKey>(() => generateSync(length: length));
  }

  /// Generates a new [SecretKey] synchronously.
  /// You can optionally define key `length` (in bytes).
  SecretKey generateSync({int length}) {
    length ??= defaultLength;
    if (validLengths != null && !validLengths.contains(length)) {
      throw ArgumentError.value(
        length,
        'length',
        'Not a valid length',
      );
    }
    return SecretKey.randomBytes(length);
  }

  /// Tells whether the key length (in bytes) is valid.
  bool isValidLength(int length) {
    if (validLengths == null) {
      return true;
    }
    return validLengths.contains(length);
  }
}
