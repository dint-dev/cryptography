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

library web_crypto;

import 'dart:async';
import 'dart:convert';
import 'dart:html' as html;
import 'dart:js' as js;
import 'dart:js_util' as js;
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/src/utils/parameters.dart';
import 'package:meta/meta.dart';

import '../algorithms/aes_impl_cbc.dart' as dart;
import '../algorithms/aes_impl_ctr.dart' as dart;
import '../algorithms/aes_impl_gcm.dart' as dart;
import '../algorithms/ec_dh_impl.dart' as dart;
import '../algorithms/ec_dsa_impl.dart' as dart;
import '../algorithms/pbkdf2_impl.dart' as dart;
import '../algorithms/sha1_sha2_impl.dart' as dart;
import 'bindings.dart' as web_crypto;

part 'impl/aes.dart';
part 'impl/aes_cbc.dart';
part 'impl/aes_ctr.dart';
part 'impl/aes_gcm.dart';
part 'impl/ec_dh.dart';
part 'impl/ec_dsa.dart';
part 'impl/hashes.dart';
part 'impl/helpers.dart';
part 'impl/pbkdf2.dart';
part 'impl/rsa.dart';
part 'impl/rsa_pss.dart';
part 'impl/rsa_ssa_pkcs1v15.dart';

bool get isWebCryptoSupported => web_crypto.subtle != null;
