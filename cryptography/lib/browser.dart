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

/// @nodoc
@Deprecated(
  'This library will be removed in a future major version.'
  ' You can find `BrowserCryptography` class in "package:cryptography_plus/cryptography_plus.dart".',
)
library cryptography_plus.browser;

export 'src/browser/browser_cryptography_when_not_browser.dart'
    if (dart.library.html) 'src/browser/browser_cryptography.dart';
