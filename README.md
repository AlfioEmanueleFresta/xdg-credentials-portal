# libwebauthn

A Linux-native implementation of FIDO2 and FIDO U2F Platform API, fully written in Rust.

This library supports multiple transports (see [Transports][#transports] for a list) via a pluggable interface, making it easy to add additional backends.

## The Linux Credentials Project

This project is now part of [The Linux Credentials Project](linux-credentials), and was previously known as **xdg-credentials-portal**.

[The Linux Credentials Project](linux-credentials) aims to offer FIDO2 platform functionality (FIDO U2F, and WebAuthn) on Linux, over a [D-Bus Portal interface][xdg-portal].

_Looking for the D-Bus API proposal?_ Check out [platform-api][linux-credentials].

## Features

- FIDO U2F
  - 🟢 Registration (U2F_REGISTER)
  - 🟢 Authentication (U2F_AUTHENTICATE)
  - 🟢 Version (U2F_VERSION)
- FIDO2
  - 🟢 Create credential
  - 🟢 Verify assertion
  - 🟢 Biometric user verification
  - 🟢 Discoverable credentials (resident keys)
- FIDO2 to FIDO U2F downgrade
  - 🟢 Basic functionality
  - 🟢 Support for excludeList and pre-flight requests
- PIN/UV Protocols
  - 🟢 PIN/UV Auth Protocol One
  - 🟢 PIN/UV Auth Protocol Two
- PIN/UV Operations
  - 🟢 GetPinToken
  - 🟢 GetPinUvAuthTokenUsingPinWithPermissions
  - 🟢 GetPinUvAuthTokenUsingUvWithPermissions
- [Passkey Authentication][passkeys]
  - 🟢 Discoverable credentials (resident keys)
  - 🟢 Hybrid transport (caBLE v2): QR-initiated transactions ([#52][#52]: iOS only)
  - 🟠 Hybrid transport (caBLE v2): State-assisted transactions ([#31][#31]: planned)

## Transports

|                      | USB (HID)                 | Bluetooth Low Energy (BLE) | NFC                   | TPM 2.0 (Platform)    | Hybrid (caBLEv2)                   |
| -------------------- | ------------------------- | -------------------------- | --------------------- | --------------------- | ---------------------------------- |
| **FIDO U2F**         | 🟢 Supported (via hidapi) | 🟢 Supported (via bluez)   | 🟠 Planned ([#5](#5)) | 🟠 Planned ([#4][#4]) | N/A                                |
| **WebAuthn (FIDO2)** | 🟢 Supported (via hidapi) | 🟢 Supported (via bluez)   | 🟠 Planned ([#5](#5)) | 🟠 Planned ([#4][#4]) | 🟠 Partly implemented ([#31][#31]) |

## Contributing

Contributions are very welcome!

If you'd like to contribute but you don't know where to start, check out the _Issues_ tab of [each repository][#repositories].

[linux-credentials]: https://github.com/linux-credentials
[webauthn]: https://www.w3.org/TR/webauthn/
[firefox-hello]: https://blog.mozilla.org/security/2019/03/19/passwordless-web-authentication-support-via-windows-hello/
[flatpak-issue]: https://github.com/flatpak/flatpak/issues/2764
[firefox-flathub]: https://flathub.org/apps/details/org.mozilla.firefox
[fido-android]: https://fidoalliance.org/news-your-google-android-7-phone-is-now-a-fido2-security-key/
[fido-android-api]: https://developers.google.com/identity/fido/android/native-apps
[android-fido-unprivileged]: https://developers.google.com/android/reference/com/google/android/gms/fido/fido2/Fido2ApiClient
[android-fido-unprivileged-cert]: https://developers.google.com/identity/fido/android/native-apps#interoperability_with_your_website
[android-fido-privileged]: https://developers.google.com/android/reference/com/google/android/gms/fido/fido2/Fido2PrivilegedApiClient
[apple-apis]: https://developer.apple.com/documentation/authenticationservices/aswebauthenticationsession
[#10]: https://github.com/AlfioEmanueleFresta/xdg-credentials-portal/issues/10
[#3]: https://github.com/AlfioEmanueleFresta/xdg-credentials-portal/issues/3
[#4]: https://github.com/AlfioEmanueleFresta/xdg-credentials-portal/issues/4
[#5]: https://github.com/AlfioEmanueleFresta/xdg-credentials-portal/issues/5
[#17]: https://github.com/AlfioEmanueleFresta/xdg-credentials-portal/issues/17
[#18]: https://github.com/AlfioEmanueleFresta/xdg-credentials-portal/issues/18
[#31]: https://github.com/AlfioEmanueleFresta/xdg-credentials-portal/issues/31
[passkeys]: https://fidoalliance.org/passkeys/
