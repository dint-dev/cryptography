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

import 'package:kms/kms.dart';

import 'browser_kms_impl_vm.dart'
    if (dart.library.html) 'browser_kms_impl_browser.dart' as impl;

/// Stores cryptographic keys in _window.localStorage_.
///
/// If you can separate different KMS instances with [namespace].
///
/// If you give [secretKey] in the constructor, the secret key will be used for
/// encrypting the stored keys.
abstract class BrowserKms extends Kms {
  /// Returns KMS when called in browsers and null when called in other
  /// platforms.
  static BrowserKms get({String namespace, SecretKey secretKey}) {
    return impl.newBrowserKms(namespace: namespace, secretKey: secretKey);
  }

  factory BrowserKms._() {
    throw UnimplementedError();
  }
}
