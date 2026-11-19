# Responsible Disclosure of DreameHome Android, Cloud, and MQTT Security Vulnerabilities

Researcher: Jose Lomeli<br>
Contact: jelvmx@proton.me<br>
Developer: Dreame Innovation Technology (Suzhou) Co., Ltd. (`追觅创新科技（苏州）有限公司`)<br>
Product: DreameHome Android application and supporting cloud services<br>
Android package: `com.dreame.smartlife`
Published: November 19, 2026

## What is DreameHome?

DreameHome is a connected-device platform with mobile applications for Android and iOS. The applications let users connect and control supported robot vacuums, robotic lawn mowers, and robotic pool cleaners. Depending on the device, users can manage maps, schedules, sharing, and camera or video features. Account, device, map, and camera data are exchanged with Dreame's cloud services.

This research assessed DreameHome 2.5.6.4 for Android, a researcher-owned robot vacuum and camera, and the platform's supporting cloud, MQTT, and media services.

## Summary

The security assessment covered version 2.5.6.4 of the DreameHome Android application and its supporting services tested in May and June 2026. As a result of the assessment, six (6) core vulnerabilities were found and are documented here. The findings affected cloud API authorization, MQTT access control, device sharing, camera binding, and Android plugin integrity.

Any authenticated DreameHome account could submit another user's UID and obtain that user's Meari session credentials. UIDs were obtainable through public forum profiles indexed into the 400,000s, an after-sales file containing 2,684 UIDs, and an email-to-UID lookup. For Meari-backed camera accounts, the demonstrated chain reached live video, microphone audio, the camera speaker, and stored recordings. This exposed activity inside the home to another account.

The other findings disclosed household map frames (LiDAR) and home-network details, continued delivering telemetry after sharing was revoked, let non-owners enter and publish to a device's live-video channel, or transferred a camera's Dreame account binding. The Android finding allowed modified feature code to run inside the app.

Dreame acknowledged the coordinated disclosure and treated the findings with seriousness in its response. I would like to thank its security team for reviewing the assessment, providing remediation plans, and discussing the follow-up results.

I would also like to thank Wade Sparks III and VulnCheck for their support throughout the disclosure process and for coordinating the CVE allocations.

## Versions

- Affected Android application: DreameHome 2.5.6.4.
- Tested devices: Dreame L10s Pro Gen3 (`dreame.vacuum.r9542b`) and NAVO Care SE 1 InCam (`dreame.ipc.a121mr`).
- The initial assessment was performed in May 2026, and remediation retesting ran from September 9 to October 20, 2026.

## Findings

### CVE-2026-49960: Any authenticated user can obtain another user's camera credentials via the login bridge

<table class="metatable">
<tr><th>Severity</th><td>Critical, 9.6</td></tr>
<tr><th>CVSS 3.1</th><td><code>CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N</code></td></tr>
<tr><th>Component</th><td>Cloud API and camera-platform account bridge</td></tr>
<tr><th>Weakness</th><td>CWE-639 - Authorization Bypass Through User-Controlled Key</td></tr>
<tr><th>Status</th><td>Fixed</td></tr>
</table>

The cloud endpoint `POST /smart-app/meari-cloud/redirectAndLogin` used a caller-supplied `uid` to select a Meari camera-platform account. It did not verify that the UID belonged to the account authenticated by the `Dreame-Auth` token. Any authenticated DreameHome user could supply another account's UID and receive that account's Meari identity and session credentials. UIDs were obtainable from public forum profiles, the after-sales file, and the account lookup that resolved email addresses to UIDs.

For Meari-backed camera accounts, the leaked credentials exposed camera connection material. We used the separately documented media path to view live video, hear microphone audio, speak through the camera's speaker, and browse stored recordings on a test camera. The account bridge selected its target by UID, so the tested camera model was not part of the authorization decision.

### CVE-2026-49961: Any authenticated user can receive another vacuum's home maps and telemetry via MQTT

<table class="metatable">
<tr><th>Severity</th><td>Medium, 6.5</td></tr>
<tr><th>CVSS 3.1</th><td><code>CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N</code></td></tr>
<tr><th>Component</th><td>MQTT broker</td></tr>
<tr><th>Weakness</th><td>CWE-863 - Incorrect Authorization</td></tr>
<tr><th>Status</th><td>Fixed</td></tr>
</table>

The MQTT broker accepted subscriptions to `/status/{DID}/{UID}/{model}/#` without verifying that the authenticated account owned or could access the device. Any authenticated DreameHome user with the DID, owner UID, and model could subscribe to another device's status topic.

During an active cleaning session, a non-owner account received 29 messages in 120 seconds, including 20 compressed LiDAR map frames. Those frames exposed the home's mapped layout. The messages also disclosed the vacuum's Wi-Fi SSID and BSSID, local IP address, gateway, and firmware version. The sharing workflow described under CVE-2026-49962 supplied the topic identifiers.

### CVE-2026-49962: Former share recipients retain MQTT access after revocation

<table class="metatable">
<tr><th>Severity</th><td>Medium, 5.7</td></tr>
<tr><th>CVSS 3.1</th><td><code>CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N</code></td></tr>
<tr><th>Component</th><td>Device sharing and MQTT authorization</td></tr>
<tr><th>Weakness</th><td>CWE-863 - Incorrect Authorization</td></tr>
<tr><th>Status</th><td>Fixed</td></tr>
</table>

The device-sharing workflow exposed the DID, owner UID, and model to a recipient. After the owner revoked sharing, the former recipient lost normal application access and the device-command API rejected its requests. The MQTT broker still accepted subscriptions to the device's status topic.

The former recipient received eight messages in 60 seconds after revocation, including map data. Revoking the share removed normal application access but left the former recipient able to monitor the home's map and device status through MQTT.

### CVE-2026-49963: MD5-only React Native plugin check accepts tampered code

<table class="metatable">
<tr><th>Severity</th><td>High, 8.0</td></tr>
<tr><th>CVSS 3.1</th><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N</code></td></tr>
<tr><th>Component</th><td>Android application</td></tr>
<tr><th>Weakness</th><td>CWE-494 - Download of Code Without Integrity Check</td></tr>
<tr><th>Status</th><td>Fixed</td></tr>
</table>

The Android application downloaded React Native feature bundles and ran their JavaScript inside DreameHome. `RnPluginDownloadManager.java` checked a bundle's MD5 against a value stored by the client, but did not authenticate the code's publisher. A network-positioned attacker able to replace both the bundle and its MD5 metadata could make the check accept modified code.

Replacing both values on a rooted test phone caused injected JavaScript to run inside DreameHome for camera and vacuum feature bundles. That code ran with the application's permissions and access to the same bridge APIs as a legitimate plugin.

### CVE-2026-49964: Any authenticated user can obtain another device's live-video channel token

<table class="metatable">
<tr><th>Severity</th><td>High, 8.5</td></tr>
<tr><th>CVSS 3.1</th><td><code>CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N</code></td></tr>
<tr><th>Component</th><td>Cloud API and Agora real-time channel</td></tr>
<tr><th>Weakness</th><td>CWE-639 - Authorization Bypass Through User-Controlled Key</td></tr>
<tr><th>Status</th><td>Fixed</td></tr>
</table>

The cloud endpoint `POST /dreame-user-iot/token/rtc2` issued an Agora RTC token for caller-supplied device and owner identifiers without verifying device ownership. The token is the credential used to join the device's live-video channel. Any authenticated DreameHome user with a device DID and owner UID could request one for that device.

Agora accepted the issued token and admitted the non-owner client to the device's live-video channel. The token also permitted video publication. The separately documented MQTT access-control flaw exposed the SM4 session key used for encrypted video. In a controlled test of a supported camera model, DreameHome displayed video published under the targeted device's identity.

### CVE-2026-49965: Any authenticated user can reassign another user's camera binding

<table class="metatable">
<tr><th>Severity</th><td>High, 7.1</td></tr>
<tr><th>CVSS 3.1</th><td><code>CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:L</code></td></tr>
<tr><th>Component</th><td>Cloud camera-binding API</td></tr>
<tr><th>Weakness</th><td>CWE-639 - Authorization Bypass Through User-Controlled Key</td></tr>
<tr><th>Status</th><td>Fixed</td></tr>
</table>

The cloud endpoint `POST /smart-app/meari-cloud/bindDevice` accepted a binding request from an authenticated account that did not own the camera. A caller with the camera identifiers could supply its own user identity and change the camera's Dreame account binding.

The camera disappeared from the original owner's Dreame device list, appeared in the other account's list, and recorded that account as `masterUid`. The request therefore transferred the Dreame account binding and denied the owner access to the camera through DreameHome until the binding was restored.

## Finding chains

The findings combined into several distinct attack paths:

1. **Camera-platform credentials and media access.** Public forum profiles, the after-sales file, and the email-to-UID lookup supplied target UIDs. CVE-2026-49960 converted a UID into another account's Meari credentials. The camera platform accepted them, and the documented media path reached live video, microphone audio, the camera speaker, and stored recordings on a test camera.
2. **Vacuum telemetry after sharing revocation.** The sharing workflow exposed the identifiers required for an MQTT status topic. CVE-2026-49961 allowed a non-owner account to subscribe and receive maps and network telemetry. CVE-2026-49962 allowed the former sharing recipient to continue receiving those messages after the owner revoked access.
3. **RTC channel admission and media access.** Device identifiers available through sharing could be supplied to CVE-2026-49964. The endpoint returned a token that let a non-owner enter the device's live-video channel. CVE-2026-49961 exposed the session key used for encrypted video. In a controlled test, DreameHome displayed video published under the targeted device's identity.

## Remediation status

All six CVE-listed findings are Fixed.

## Coordinated disclosure timeline

- **May 18, 2026:** Dreame was notified, and a 90-day coordinated-disclosure period was proposed.
- **June 11, 2026:** Dreame acknowledged the disclosure and requested the complete technical assessment.
- **June 16, 2026:** The complete assessment was delivered to Dreame.
- **June 24, 2026:** Dreame supplied a per-finding response and planned remediation dates.
- **July 24, 2026:** Dreame requested that public disclosure of CVE-2026-49963 be postponed to August 31 to match its revised remediation schedule.
- **August 5, 2026:** The researcher agreed to the August 31 disclosure date for CVE-2026-49963.
- **September 4, 2026:** Dreame reported that the findings had been fixed and identified Android 2.6.4.0 and iOS 2.6.3 as the updated application versions.
- **September 9, 2026:** Remediation verification against Android 2.6.4.0.
- **October 14, 2026:** Dreame reported that the previously discussed vulnerabilities had been fixed.
- **October 15, 2026:** The remediation-retest results were delivered to Dreame with several items still reproducible.
- **October 26, 2026:** Dreame reported fixes for the MQTT authorization and share-revocation findings and said the camera-binding finding remained under investigation.
- **November 19, 2026:** Public disclosure.

## Credit

Research and coordinated disclosure: Jose Lomeli.

CVE allocation and disclosure support: Wade Sparks III and VulnCheck.
