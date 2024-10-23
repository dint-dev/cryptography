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

/// Test utilities for [HashAlgorithm] classes.
///
/// ## Example
/// See [testHashAlgorithm].
library cryptography_plus_test.hash_algorithm;

import 'dart:async';
import 'dart:typed_data';

import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:cryptography_plus/dart.dart';
import 'package:test/test.dart';

import 'hex.dart';

HashAlgorithm? _hashAlgorithm;

/// Tests a hash algorithm.
///
/// ## Example
/// ```dart
/// import 'package:cryptography_test/hash.dart';
///
/// void main() {
///   testHashAlgorithm(
///     builder: () => MyAlgorithm(),
///     otherTests: () {
///       test('something', () {
///         // ...
///       });
///     },
///   );
/// }
/// ```
void testHashAlgorithm({
  required HashAlgorithm Function() builder,
  required void Function()? otherTests,
}) {
  group('${builder()}:', () {
    setUp(() {
      _hashAlgorithm = builder();
    });
    tearDown(() {
      _hashAlgorithm = null;
    });
    for (var i = 0; i < 100; i++) {
      final data = Uint8List(i);
      for (var i = 0; i < data.length; i++) {
        data[i] = i;
      }
      testHashExample(
        summary: 'Hashing $i bytes',
        input: data,
        expected: () async => await _hashAlgorithm!.hash(data),
      );
    }
    if (otherTests != null) {
      otherTests();
    }
  });
}

void testHashExample({
  String? summary,
  HashAlgorithm? algorithm,
  required List<int> input,
  required FutureOr<Hash> Function() expected,
}) {
  final finalAlgorithm = algorithm;
  group(summary ?? 'Example', () {
    test('algorithm.hash(...)', () async {
      final algorithm = finalAlgorithm ?? _hashAlgorithm!;
      final hash = await algorithm.hash(input);
      final expectedHash = await expected();
      expect(
        hexFromBytes(hash.bytes),
        hexFromBytes(expectedHash.bytes),
      );
    });

    test('algorithm.newState(): add(firstHalf), add(secondHalf), close()',
        () async {
      final algorithm = finalAlgorithm ?? _hashAlgorithm!;
      final state = algorithm.newHashSink();
      final half = input.length ~/ 2;
      state.add(input.sublist(0, half));
      state.add(input.sublist(half));
      state.close();
      final hash = await algorithm.hash(input);
      final expectedHash = await expected();
      expect(
        hexFromBytes(hash.bytes),
        hexFromBytes(expectedHash.bytes),
      );

      // Try reset and doing the same again
      if (state is DartHashSink) {
        state.reset();
        state.add(input.sublist(0, half));
        state.add(input.sublist(half));
        state.close();
        final hash = await algorithm.hash(input);
        final expectedHash = await expected();
        expect(
          hexFromBytes(hash.bytes),
          hexFromBytes(expectedHash.bytes),
        );
      }
    });

    test('algorithm.newState(): addSlice(..., true)', () async {
      final algorithm = finalAlgorithm ?? _hashAlgorithm!;
      final state = algorithm.newHashSink();
      state.addSlice(input, 0, input.length, true);
      final hash = await algorithm.hash(input);
      final expectedHash = await expected();
      expect(
        hexFromBytes(hash.bytes),
        hexFromBytes(expectedHash.bytes),
      );

      // Try reset and doing the same again
      if (state is DartHashSink) {
        state.reset();
        state.addSlice(input, 0, input.length, true);
        final hash = await algorithm.hash(input);
        final expectedHash = await expected();
        expect(
          hexFromBytes(hash.bytes),
          hexFromBytes(expectedHash.bytes),
        );
      }
    });

    test(
        'algorithm.newState(): addSlice(.., 0, mid, false), addSlice(..., mid, end, true)',
        () async {
      final middle = input.length ~/ 2;

      final algorithm = finalAlgorithm ?? _hashAlgorithm!;
      final state = algorithm.newHashSink();
      state.addSlice(input, 0, middle, false);
      state.addSlice(input, middle, input.length, true);
      final hash = await algorithm.hash(input);
      final expectedHash = await expected();
      expect(
        hexFromBytes(hash.bytes),
        hexFromBytes(expectedHash.bytes),
      );

      // Try reset and doing the same again
      if (state is DartHashSink) {
        state.reset();
        state.addSlice(input, 0, middle, false);
        state.addSlice(input, middle, input.length, true);
        final hash = await algorithm.hash(input);
        final expectedHash = await expected();
        expect(
          hexFromBytes(hash.bytes),
          hexFromBytes(expectedHash.bytes),
        );
      }
    });

    test('algorithm.newState(): addSlice(.., false), addSlice(..., 0, 0, true)',
        () async {
      final algorithm = finalAlgorithm ?? _hashAlgorithm!;
      final state = algorithm.newHashSink();
      state.addSlice(input, 0, input.length, false);
      state.addSlice(input, 0, 0, true);
      final hash = await algorithm.hash(input);
      final expectedHash = await expected();
      expect(
        hexFromBytes(hash.bytes),
        hexFromBytes(expectedHash.bytes),
      );

      // Try reset and doing the same again
      if (state is DartHashSink) {
        state.reset();
        state.addSlice(input, 0, input.length, false);
        state.addSlice(input, 0, 0, true);
        final hash = await algorithm.hash(input);
        final expectedHash = await expected();
        expect(
          hexFromBytes(hash.bytes),
          hexFromBytes(expectedHash.bytes),
        );
      }
    });
  });
}

class HashExample {
  final String? summary;
  final List<int> input;
  final List<int> expected;

  HashExample({
    this.summary,
    required this.input,
    required this.expected,
  });
}
