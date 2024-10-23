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

/// An optimized version of [package:cryptography](https://pub.dev/packages/cryptography).
///
/// See [FlutterCryptography] for usage instructions.
library cryptography_flutter_plus;

import 'package:cryptography_flutter_plus/cryptography_flutter_plus.dart';

export 'src/background/background_aes_gcm.dart';
export 'src/background/background_chacha20.dart';
export 'src/background/background_cipher.dart';
export 'src/background/background_pbkdf2.dart';
export 'src/cryptography_channel_policy.dart';
export 'src/cryptography_channel_queue.dart';
export 'src/cryptography_unsupported_error.dart';
export 'src/flutter/flutter_aes_gcm.dart';
export 'src/flutter/flutter_chacha20.dart';
export 'src/flutter/flutter_cipher.dart';
export 'src/flutter/flutter_ecdh.dart';
export 'src/flutter/flutter_ecdsa.dart';
export 'src/flutter/flutter_ed25519.dart';
export 'src/flutter/flutter_pbkdf2.dart';
export 'src/flutter/flutter_rsa_pss.dart';
export 'src/flutter/flutter_rsa_ssa_pkcs1v15.dart';
export 'src/flutter/flutter_x25519.dart';
export 'src/flutter_cryptography.dart';
