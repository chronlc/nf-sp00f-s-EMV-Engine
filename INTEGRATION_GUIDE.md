# nf-sp00f EMV Engine - Integration Guide

## How to Import and Use the EMV Engine in Your Android Project

### Method 1: Direct Source Integration (Recommended for Development)

#### Step 1: Clone the Repository
```bash
git clone https://github.com/chronlc/nf-sp00f-s-EMV-Engine.git
cd nf-sp00f-s-EMV-Engine
```

#### Step 2: Copy Library Module
```bash
# Copy the entire Android EMV library module to your project
cp -r "Android EMV" /path/to/your/project/emv-library
```

#### Step 3: Add Module to Your Project
**In your project's `settings.gradle.kts`:**
```kotlin
include(":app")
include(":emv-library")
project(":emv-library").projectDir = file("emv-library")
```

**In your app's `build.gradle.kts`:**
```kotlin
dependencies {
    implementation(project(":emv-library"))
    // ... other dependencies
}
```

### Method 2: AAR Library Distribution (For Production)

#### Step 1: Build the AAR Library
```bash
cd "Android EMV"
./gradlew assembleRelease
# AAR will be generated in: build/outputs/aar/
```

#### Step 2: Add AAR to Your Project
**Copy AAR to your project:**
```bash
mkdir -p app/libs
cp emv-library/build/outputs/aar/emv-library-release.aar app/libs/
```

**In your app's `build.gradle.kts`:**
```kotlin
dependencies {
    implementation(files("libs/emv-library-release.aar"))
    
    // Required dependencies for EMV library
    implementation("androidx.core:core-ktx:1.12.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.2")
    implementation("com.jakewharton.timber:timber:5.0.1")
}
```

### Method 3: JitPack Distribution (Future)

**When published to JitPack, add to your `build.gradle.kts`:**
```kotlin
repositories {
    maven { url = uri("https://jitpack.io") }
}

dependencies {
    implementation("com.github.chronlc:nf-sp00f-s-EMV-Engine:latest-version")
}
```

## Basic Usage Examples

### 1. Initialize EMV Engine

```kotlin
import com.nf_sp00f.app.emv.*
import com.nf_sp00f.app.emv.nfc.*

class MainActivity : AppCompatActivity() {
    
    private lateinit var emvEngine: EmvEngine
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Initialize EMV Engine with Android Internal NFC
        emvEngine = EmvEngine.builder()
            .nfcProvider(AndroidInternalNfcProvider(this))
            .enableRocaDetection(true)
            .enableDebugLogging(BuildConfig.DEBUG)
            .build()
    }
}
```

### 2. Process EMV Transaction

```kotlin
class EmvPaymentProcessor {
    
    suspend fun processPayment(amount: Long, currency: String): TransactionResult {
        return try {
            val transactionData = TransactionData(
                amount = amount,
                currency = currency,
                transactionType = TransactionType.PURCHASE,
                timestamp = System.currentTimeMillis()
            )
            
            emvEngine.processTransaction(transactionData)
            
        } catch (e: Exception) {
            TransactionResult.Error("Transaction failed: ${e.message}")
        }
    }
    
    fun handleTransactionResult(result: TransactionResult) {
        when (result) {
            is TransactionResult.Success -> {
                val cardData = result.cardData
                val pan = cardData.pan?.let { maskPan(it) }
                val expiry = cardData.expiry
                
                // Display success UI
                showTransactionSuccess(pan, expiry, result.amount)
            }
            
            is TransactionResult.Error -> {
                // Display error UI
                showTransactionError(result.errorMessage)
            }
        }
    }
    
    private fun maskPan(pan: String): String {
        return if (pan.length >= 8) {
            "${pan.take(4)}****${pan.takeLast(4)}"
        } else pan
    }
}
```

### 3. Dual NFC Provider Setup

```kotlin
class DualNfcSetup {
    
    suspend fun setupDualNfcProviders(): EmvEngine {
        // Option 1: Android Internal NFC
        val androidProvider = AndroidInternalNfcProvider(context)
        
        // Option 2: PN532 Bluetooth NFC
        val pn532Provider = Pn532BluetoothNfcProvider().apply {
            setBluetoothDevice(
                address = "98:D3:31:F5:69:42", // Your HC-06 MAC address
                name = "PN532-HC06"
            )
        }
        
        // Initialize with preferred provider
        return EmvEngine.builder()
            .nfcProvider(androidProvider) // or pn532Provider
            .enableRocaDetection(true)
            .build()
    }
    
    suspend fun switchNfcProvider(engine: EmvEngine, usePN532: Boolean) {
        val newProvider = if (usePN532) {
            Pn532BluetoothNfcProvider().apply {
                setBluetoothDevice("98:D3:31:F5:69:42", "PN532-HC06")
            }
        } else {
            AndroidInternalNfcProvider(context)
        }
        
        // Reinitialize engine with new provider
        engine.updateNfcProvider(newProvider)
    }
}
```

### 4. Command Interface Usage

```kotlin
import com.nf_sp00f.app.emv.command.*

class AdvancedEmvOperations {
    
    private val commandInterface = EmvCommandInterface()
    
    suspend fun performCardAnalysis(): SecurityAnalysisResult {
        // Create session
        val sessionId = commandInterface.createSession(nfcProvider)
        
        try {
            // Execute card detection
            val cardResult = commandInterface.executeCardDetection(
                CommandContext(sessionId, nfcProvider)
            )
            
            if (cardResult is CommandResult.Success) {
                val cardInfo = cardResult.data
                
                // Execute security analysis
                val securityResult = commandInterface.executeSecurityAnalysis(
                    CommandContext(sessionId, nfcProvider)
                )
                
                return when (securityResult) {
                    is CommandResult.Success -> securityResult.data
                    is CommandResult.Error -> SecurityAnalysisResult.failed(securityResult.message)
                    is CommandResult.Timeout -> SecurityAnalysisResult.failed("Analysis timeout")
                }
            } else {
                return SecurityAnalysisResult.failed("Card detection failed")
            }
            
        } finally {
            commandInterface.closeSession(sessionId)
        }
    }
}
```

### 5. JSON Data Export

```kotlin
import com.nf_sp00f.app.emv.json.*

class EmvDataExport {
    
    private val jsonProcessor = EmvJsonProcessor()
    
    suspend fun exportTransactionData(
        sessionId: String,
        cardInfo: CardInfo,
        tlvDatabase: TlvDatabase,
        transactions: List<TransactionResult>
    ): String {
        
        return jsonProcessor.exportSessionToJson(
            sessionId = sessionId,
            cardInfo = cardInfo,
            tlvDatabase = tlvDatabase,
            transactionResults = transactions,
            authenticationResults = emptyList(),
            nfcProviderInfo = nfcProvider.getProviderInfo(),
            format = JsonExportFormat.PRETTY,
            scope = JsonExportScope.COMPLETE_EXPORT
        )
    }
    
    fun saveExportToFile(jsonData: String, filename: String) {
        val file = File(context.getExternalFilesDir(null), "$filename.json")
        file.writeText(jsonData)
    }
}
```

## Required Permissions

**Add to your `AndroidManifest.xml`:**
```xml
<!-- NFC Permissions -->
<uses-permission android:name="android.permission.NFC" />
<uses-feature 
    android:name="android.hardware.nfc" 
    android:required="false" />

<!-- Bluetooth Permissions (for PN532) -->
<uses-permission android:name="android.permission.BLUETOOTH" />
<uses-permission android:name="android.permission.BLUETOOTH_ADMIN" />
<uses-permission android:name="android.permission.ACCESS_COARSE_LOCATION" />

<!-- For Android 12+ -->
<uses-permission android:name="android.permission.BLUETOOTH_CONNECT" />
<uses-permission android:name="android.permission.BLUETOOTH_SCAN" />

<!-- File Storage (for exports) -->
<uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
```

## ProGuard Configuration

**Add to your `proguard-rules.pro`:**
```proguard
# nf-sp00f EMV Engine
-keep class com.nf_sp00f.app.emv.** { *; }
-keep interface com.nf_sp00f.app.emv.** { *; }

# Serialization
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.AnnotationsKt

# Coroutines
-keepclassmembers class kotlinx.coroutines.internal.MainDispatcherFactory {
    void <init>();
}
```

## Build Requirements

### Minimum Requirements
- **Android API 21+** (Android 5.0+)
- **Kotlin 1.9.0+**
- **Target SDK 34**
- **Java 17** (for build)

### Development Environment
- **Android Studio** Flamingo or later
- **Android SDK** with platform-tools
- **NFC-capable device** for testing

## Testing Your Integration

### 1. Basic Integration Test
```kotlin
@Test
fun testEmvEngineInitialization() {
    val emvEngine = EmvEngine.builder()
        .nfcProvider(MockNfcProvider())
        .build()
    
    assertThat(emvEngine).isNotNull()
    assertThat(emvEngine.isInitialized()).isTrue()
}
```

### 2. Transaction Test
```kotlin
@Test
suspend fun testTransactionProcessing() {
    val result = emvEngine.processTransaction(
        TransactionData(
            amount = 1000L,
            currency = "USD",
            transactionType = TransactionType.PURCHASE
        )
    )
    
    // Verify result structure
    when (result) {
        is TransactionResult.Success -> {
            assertThat(result.cardData.pan).isNotNull()
            assertThat(result.amount).isEqualTo(1000L)
        }
        is TransactionResult.Error -> {
            // Handle expected test errors
        }
    }
}
```

## Troubleshooting

### Common Issues

1. **Build Errors:**
   - Ensure Android SDK path is correct in `local.properties`
   - Check Kotlin version compatibility
   - Verify all dependencies are included

2. **NFC Issues:**
   - Check device NFC capability
   - Verify NFC permissions in manifest
   - Test with known EMV cards

3. **PN532 Bluetooth Issues:**
   - Ensure HC-06 is paired with correct MAC address
   - Check Bluetooth permissions for Android 12+
   - Verify UART baud rate (115200)

### Support

- **Repository:** https://github.com/chronlc/nf-sp00f-s-EMV-Engine
- **Documentation:** See README.md for complete function reference
- **Issues:** Create GitHub issues for bug reports or feature requests

---

**Ready to process EMV transactions with advanced security features!** 🚀