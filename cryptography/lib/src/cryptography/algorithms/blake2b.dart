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

import 'package:cryptography/cryptography.dart';

import 'blake2b_impl.dart';

/// _BLAKE2B_ hash function ([RFC 7693](https://tools.ietf.org/html/rfc7693)).
///
/// ## Asynchronous usage
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   final message = <int>[1,2,3];
///
///   final hash = await blake2b.hash(
///     message,
///   );
///
///   print('Hash: ${hash.bytes}');
/// }
/// ```
///
/// ## Synchronous usage
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// void main() {
///   // Create a sink
///   final sink = blake2b.newSink();
///
///   // Add any number of chunks
///   sink.add(<int>[1,2,3]);
///   sink.add(<int>[4,5]);
///
///   // Calculate the hash
///   sink.close();
///   final hash = sink.hash;
///
///   print('Hash: ${hash.bytes}');
/// }
/// ```
const HashAlgorithm blake2b = Blake2b();
