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

import 'package:flutter/foundation.dart';

/// Describes when to pass computation to plugin or another isolate.
class CryptographyChannelPolicy {
  static const CryptographyChannelPolicy never = CryptographyChannelPolicy(
    minLength: 0,
    maxLength: 0,
  );

  /// Minimum length of data for processing in the plugin.
  final int minLength;

  /// Maximum length of data for processing in the plugin.
  final int? maxLength;

  const CryptographyChannelPolicy({
    required this.minLength,
    required this.maxLength,
  });

  bool matches({required int length}) {
    if (kIsWeb || length < minLength) {
      return false;
    }
    final maxLength = this.maxLength;
    return maxLength == null || length < maxLength;
  }
}
