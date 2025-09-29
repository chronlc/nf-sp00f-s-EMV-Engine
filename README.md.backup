# nf-sp00f EMV Engine 🏆

**Advanced Android EMV Processing Library with Dual NFC Support**

[![Kotlin](https://img.shields.io/badge/Kotlin-100%25-0095D5.svg)](https://kotlinlang.org/)
[![Android](https://img.shields.io/badge/Android-API%2021+-3DDC84.svg)](https://android.com/)
[![NFC](https://img.shields.io/badge/NFC-Internal%20%2B%20PN532-FF6B35.svg)](https://developer.android.com/guide/topics/connectivity/nfc)
[![EMV](https://img.shields.io/badge/EMV-L1%20%2B%20L2-00A86B.svg)](https://www.emvco.com/)

## 🚀 **Project Overview**

**nf-sp00f EMV Engine** is a comprehensive **pure Kotlin** implementation of EMV (Europay, Mastercard, Visa) payment processing, ported from the proven **Proxmark3 Iceman Fork EMV Engine**. Designed specifically for Android applications requiring advanced contactless payment analysis and processing.

### ✨ **Key Features**

- 🏗️ **Pure Kotlin Architecture** - Zero JNI overhead, full Android optimization
- 📱 **Dual NFC Provider Support** - Android Internal NFC + PN532 via Bluetooth UART
- 🔒 **Complete Security Suite** - ROCA vulnerability detection (CVE-2017-15361)
- ⚡ **High Performance** - Optimized for mobile EMV transaction processing
- 🛡️ **EMV L1/L2 Compliance** - Full ISO 14443 Type A/B support
- 🔧 **Modular Design** - Clean architecture with dependency injection
- 📊 **Comprehensive Coverage** - 120+ functions from Proxmark3 EMV codebase

## 📋 **Project Status**

```
🎯 Architecture:     ✅ COMPLETE (100%)
🔧 Build System:     ✅ COMPLETE (100%) 
📊 Function Analysis: ✅ COMPLETE (120+ functions)
🏗️ Implementation:   🚧 IN PROGRESS (0%)
🧪 Testing Suite:    📋 PLANNED
📖 Documentation:    🚧 IN PROGRESS
```

## 🏗️ **Architecture Overview**

### **Core Components**

```
nf-sp00f EMV Engine
├── 🔧 TLV Processing Engine    (33 functions)
├── 🏦 EMV Transaction Core     (14 functions)  
├── 🔐 Cryptographic Suite     (46 functions)
├── 🛡️ Security & Auth         (12 functions)
├── 📊 Data Processing         (35 functions)
├── 🛠️ Utilities & Helpers     (18 functions)
└── 💻 Command Interface       (20+ functions)
```

### **NFC Provider Architecture**

```kotlin
interface INfcProvider {
    suspend fun exchangeApdu(apdu: ByteArray): ApduResult
    suspend fun isConnected(): Boolean
    suspend fun connect(): Boolean
    suspend fun disconnect()
}

// Implementations:
class AndroidNfcProvider    // Internal NFC (IsoDep, NfcA, NfcB)
class Pn532BluetoothProvider // PN532 via HC-06 UART
```

## 📦 **Project Structure**

```
nf-sp00f EMV Engine/
├── 📁 Android EMV/                 # Main Kotlin library
│   ├── build.gradle.kts           # Android library configuration
│   └── src/main/kotlin/com/nf_sp00f/app/emv/
│       ├── EmvEngine.kt            # Main EMV processing engine
│       ├── nfc/                    # NFC provider implementations
│       ├── tlv/                    # TLV processing engine
│       ├── crypto/                 # Cryptographic operations
│       ├── security/               # ROCA detection & validation
│       └── utils/                  # Utilities and helpers
├── 📁 Proxmark EMV/               # Reference C implementation
├── 📁 Work/                       # Development artifacts
│   ├── KOTLIN_FUNCTION_INVENTORY.md # Complete function mapping
│   └── build_emv_library.sh      # Build automation
├── 📁 .github/instructions/       # Project guidelines
└── 📄 README.md                   # This file
```

## 🛠️ **Development Environment**

### **Requirements**
- **Android Studio** - Latest stable version
- **Kotlin** - 1.9.0+
- **Android SDK** - API 21+ (Android 5.0+)
- **NDK** - For build configuration
- **Java** - OpenJDK 17

### **Environment Paths**
```bash
JAVA_HOME=/opt/openjdk-bin-17
ANDROID_SDK_ROOT=/home/user/Android/Sdk
NDK_PATH=/home/user/Android/Sdk/ndk/[version]
```

## 🚀 **Getting Started**

### **1. Clone Repository**
```bash
git clone <repository-url>
cd "EMV PORT"
```

### **2. Build Library**
```bash
chmod +x Work/build_emv_library.sh
./Work/build_emv_library.sh
```

### **3. Integration Example**
```kotlin
// Initialize EMV Engine with NFC provider
val emvEngine = EmvEngine.Builder()
    .nfcProvider(AndroidNfcProvider(context))
    .enableRocaDetection(true)
    .build()

// Process EMV transaction
val result = emvEngine.processTransaction(
    amount = 1000, // cents
    currency = "USD"
)

when (result) {
    is TransactionResult.Success -> {
        // Handle successful transaction
        val pan = result.cardData.pan
        val expiry = result.cardData.expiry
    }
    is TransactionResult.Error -> {
        // Handle transaction error
    }
}
```

## 📊 **Implementation Roadmap**

### **Phase 1: Foundation** 🔧
- [x] Project architecture and build system
- [x] Complete function analysis (120+ functions)
- [ ] **TLV Processing Engine** (33 functions)
- [ ] **Core APDU Builders** (14 functions)

### **Phase 2: Transaction Core** 🏦
- [ ] EMV transaction flow implementation
- [ ] Authentication methods (SDA/DDA/CDA)
- [ ] Certificate processing and validation

### **Phase 3: Security & Compliance** 🛡️
- [ ] ROCA vulnerability detection
- [ ] Cryptographic primitives
- [ ] EMV L1/L2 compliance validation

### **Phase 4: Advanced Features** ⚡
- [ ] JSON data exchange
- [ ] Advanced card analysis
- [ ] Performance optimization

## 🔒 **Security Features**

### **ROCA Vulnerability Protection**
- **CVE-2017-15361** detection and mitigation
- Real-time RSA key analysis
- Comprehensive vulnerability reporting

### **EMV Security Compliance**
- Static Data Authentication (SDA)
- Dynamic Data Authentication (DDA)  
- Combined Data Authentication (CDA)
- Certificate chain validation
- Cryptogram verification

## 🤝 **Contributing**

### **Development Workflow**
1. Follow **PatchPilot VSCode extension** for all file edits
2. Maintain **100% Kotlin purity** - no JNI components
3. Use **unified diff format** for code changes
4. Comprehensive **unit testing** for all functions
5. **Performance benchmarking** for critical paths

### **Code Standards**
- **Kotlin naming conventions** - PascalCase classes, camelCase methods
- **Package structure** - `com.nf_sp00f.app.emv.*`
- **Async operations** - Kotlin coroutines with proper scoping
- **Error handling** - Result<T> types with comprehensive error mapping

## 📄 **License**

This project is licensed under **MIT License** - see LICENSE file for details.

## 🙏 **Acknowledgments**

- **Proxmark3 Iceman Fork** - Original EMV implementation reference
- **Android NFC Community** - NFC/EMV implementation guidance
- **EMVCo** - EMV specifications and compliance standards

---

**nf-sp00f EMV Engine** - *Bringing advanced EMV processing to Android with uncompromising performance and security.*

🔗 **Package:** `com.nf_sp00f.app.emv`  
🏷️ **Version:** 1.0.0-alpha  
👤 **Author:** nf-sp00f  
📅 **Started:** September 28, 2025