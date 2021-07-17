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

/// [RsaPss] implemented in pure Dart.
class DartRsaPss extends RsaPss {
  @override
  final HashAlgorithm hashAlgorithm;

  final int nonceLengthInBytes;

  const DartRsaPss(
    this.hashAlgorithm, {
    this.nonceLengthInBytes = RsaPss.defaultNonceLengthInBytes,
  }) : super.constructor();

  @override
  Future<RsaKeyPair> newKeyPair(
      {int modulusLength = RsaPss.defaultModulusLength,
      List<int> publicExponent = RsaPss.defaultPublicExponent}) {
    throw UnimplementedError();
  }

  @override
  Future<Signature> sign(List<int> message, {required KeyPair keyPair}) {
    throw UnimplementedError();
  }

  @override
  Future<bool> verify(List<int> message, {required Signature signature}) {
    throw UnimplementedError();
  }
}
