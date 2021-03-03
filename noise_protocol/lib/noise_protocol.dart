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

/// A Dart implementation of
/// [Noise protocol](https://noiseprotocol.org/noise.html#the-cipherstate-object).
library noise_protocol;

import 'dart:async';
import 'dart:collection';
import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:cryptography/cryptography.dart';
import 'package:cryptography/src/utils.dart';
import 'package:meta/meta.dart';

part 'src/cipher_state.dart';
part 'src/handshake_pattern.dart';
part 'src/handshake_protocol.dart';
part 'src/handshake_result.dart';
part 'src/handshake_state.dart';
part 'src/message_pattern.dart';
part 'src/noise_authenticator.dart';
part 'src/symmetric_state.dart';
