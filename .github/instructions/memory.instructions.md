---
applyTo: '**'
description: Workspace-specific AI memory for this project
lastOptimized: '2025-09-28T21:39:45.044939+00:00'
entryCount: 3
optimizationVersion: 1
autoOptimize: true
sizeThreshold: 50000
entryThreshold: 20
timeThreshold: 7
---
# Workspace AI Memory
This file contains workspace-specific information for AI conversations.

## Professional Context
- **2025-09-28 14:39:** EMVPort project: Porting Proxmark3 Iceman Fork EMV Engine to Kotlin for Android.  
  Package: `com.nf-sp00f.app.emv`.

## Universal Laws
- **2025-09-28 14:39:** Critical rule: Use PatchPilot VSCode extension for all file edits after initial creation.  
  Never append or atomic edit files—either use PatchPilot unified diff format or delete and regenerate entire file from scratch.

## Memories/Facts
- **2025-09-28 14:39:** EMVPort project initiated for Android Kotlin port of Proxmark3 Iceman Fork EMV Engine.- **2025-09-28 14:39:** Naming conventions: Python files use snake_case. Java/Kotlin use PascalCase for classes, camelCase for methods. Package names use com.mag-sp00f.app format. Resource files use lowercase with underscores.
- **2025-09-28 14:39:** Code quality standards: Zero tolerance for placeholders, stubs, or TODO comments. All functions must be properly scoped within classes/modules. Single import block at top of files only. Production-grade code throughout with comprehensive error handling.
- **2025-09-28 14:41:** File corruption prevention protocol: When files show multiple import blocks, duplicate functions/classes, code appended after main logic, mixed naming conventions, or syntax errors from patching - immediately delete entire file and regenerate from scratch with all requirements.
- **2025-09-28 14:41:** Batch processing protocol: Load batches from batches.yaml (max 4-5 atomic tasks). Execute with pre-batch validation, corruption monitoring, post-batch audit, efficiency tracking, and memory sync with Remember MCP.
- **2025-09-28 14:41:** Security and privacy rules: No user data exposure in logs or agent scripts. No arbitrary shell command execution without review. Agent scripts never included in shipped application. All sensitive operations logged and auditable.
- **2025-09-28 14:55:** EMV Port optimized for Android internal NFC adapter. Uses IsoDep, NfcA/NfcB APIs for EMV transactions. Hardware abstraction layer bridges Proxmark3 calls to Android NFC system. Full ISO14443 Type A/B EMV compliance supported.
- **2025-09-28 15:02:** EMV Port now supports dual NFC providers: Android Internal NFC and PN532 via Bluetooth UART (HC-06). Unified interface allows seamless switching between providers. Configuration manager handles Bluetooth pairing and NFC source selection. Complete abstraction layer supports both hardware types transparently.
- **2025-09-28 15:06:** Full ROCA vulnerability detection (CVE-2017-15361) included from Proxmark3. Environment paths configured: JAVA_HOME=/opt/openjdk-bin-17, ANDROID_SDK_ROOT=/home/user/Android/Sdk. PatchPilot VSCode extension API integration mandatory for all file edits to prevent corruption. Build system configured for proper Android development environment.
