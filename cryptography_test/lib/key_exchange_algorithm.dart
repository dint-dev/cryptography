// Copyright 2023 Gohilla.
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

/// Test utilities for [KeyExchangeAlgorithm] classes.
library cryptography_test.key_exchange_algorithm;

import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';

void testKeyExchangeAlgorithm({
  required KeyExchangeAlgorithm Function() builder,
  required void Function()? otherTests,
}) {
  group('${builder()}:', () {
    setUp(() {
      _keyExchangeAlgorithm = builder();
    });
    tearDown(() {
      _keyExchangeAlgorithm = null;
    });
  });
}

KeyExchangeAlgorithm? _keyExchangeAlgorithm;

/// Currently tested [KeyExchangeAlgorithm].
KeyExchangeAlgorithm get keyExchangeAlgorithm => _keyExchangeAlgorithm!;
