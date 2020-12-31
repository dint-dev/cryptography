# Running tests
## Android
```
flutter clean
flutter emulators --launch android
flutter devices
flutter drive --driver=integration_test/driver.dart --target=integration_test/integration_test.dart -d YOUR_DEVICE_ID
```

## iOS
```
flutter clean
flutter emulators --launch ios
flutter devices
flutter drive --driver=integration_test/driver.dart --target=integration_test/integration_test.dart -d YOUR_DEVICE_ID
```