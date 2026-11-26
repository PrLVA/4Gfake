# >_ AntenaTalm Guard (Matrix Cell Guard)

> **Android Cellular Network Security & IMSI Catcher / Rogue Base Station Detector**

**AntenaTalm Guard** is an advanced open-source Android security application designed to analyze connected cellular network infrastructure, inspect surrounding cell towers, and detect potential rogue base stations, IMSI catchers (Stingrays), 2G downgrade attacks, and cellular surveillance in real-time.

---

## 🛡️ Key Security Features

- **Real-Time Modem Interrogation**: Directly queries Android's `TelephonyManager` and forces hardware-level cell scans (`requestCellInfoUpdate`) to capture active serving cells and available neighboring towers.
- **Multi-Factor Threat Analysis Engine**: Evaluates connected tower parameters against multiple security heuristics simultaneously:
  - **Forced 2G Downgrade Attack Detection**: Flags unencrypted 2G/GSM networks lacking mutual authentication.
  - **Isolated Tower (No Neighbors) Check**: Identifies strong single towers operating without overlapping neighboring cells.
  - **Invalid or Suspicious TAC / LAC Check**: Detects generic or illegal Tracking Area Codes (`0`, `65535`, `-1`) often used by IMSI catchers.
  - **Abnormally High Signal Power**: Identifies artificially boosted transmission power levels.
  - **MCC/MNC Operator Mismatch**: Verifies network operator codes against the inserted SIM card.
- **Matrix Terminal Cyberpunk UI**: Built with a sleek hacker console aesthetic featuring deep terminal blacks, glowing Matrix green (`#00FF41`), cyber amber, and crimson red alerts with monospace typography.
- **Antenna Availability Counters**: Dedicated summary cards displaying total antennas in range and available neighboring towers.
- **Manual Scan Controls**: Dedicated `[ INICIAR ]` and `[ PARAR ]` buttons with a continuous neon radar pulse animation indicating active radiofrequency surveillance.
- **CSV Audit Log Export**: Easily export real-time monitoring logs and threat assessments in CSV format for external analysis.

---

## 🔒 Permissions & Privacy

AntenaTalm Guard requires specific system permissions strictly for local network analysis:
- `ACCESS_FINE_LOCATION` / `ACCESS_COARSE_LOCATION`: **Mandatory by Android OS** to access cellular tower identifiers (*Cell ID*, *TAC*, neighbor cells). Without location services enabled, Android restricts cell info queries.
- `READ_PHONE_STATE`: Required to read mobile network operators, SIM state, and radio connection types.
- `POST_NOTIFICATIONS`: For security alerts on Android 13+.

> **Privacy Guarantee**: AntenaTalm Guard operates 100% locally on your device. It **never** collects, stores, or transmits your location GPS coordinates or cellular data to external servers.

---

## 📦 Installation & APK

The compiled debug APK is ready for installation:
- **Path**: `app/build/outputs/apk/debug/app-debug.apk`
- **Install via ADB**:
  ```bash
  adb install app/build/outputs/apk/debug/app-debug.apk
  ```

---

## 🧪 Testing

The project includes an automated JUnit test suite verifying threat scoring and heuristic analysis:
```bash
./gradlew testDebugUnitTest
```

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.
