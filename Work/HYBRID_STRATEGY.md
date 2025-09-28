# Hybrid EMV Implementation Strategy

## Phase 1: Pure Kotlin EMV Core (10-15 days)
**What:** Rewrite core EMV engine in Kotlin using Proxmark3 as reference

### 1.1 TLV Processing Engine (2-3 days)
```kotlin
class TlvEngine {
    fun parseTlv(data: ByteArray): TlvDatabase
    fun buildTlv(tags: Map<Int, ByteArray>): ByteArray  
    fun findTag(db: TlvDatabase, tag: Int): ByteArray?
}
```

### 1.2 APDU Command Builder (1-2 days)
```kotlin
class ApduBuilder {
    fun selectAid(aid: String): ByteArray
    fun getProcessingOptions(pdol: ByteArray): ByteArray
    fun readRecord(sfi: Int, record: Int): ByteArray
    fun generateAc(type: Int, cdol: ByteArray): ByteArray
}
```

### 1.3 EMV Transaction Engine (5-7 days)
```kotlin
class EmvTransactionEngine {
    suspend fun processCard(provider: INfcProvider): EmvResult
    suspend fun selectApplication(aids: List<String>): String?
    suspend fun performAuthentication(): AuthResult  
}
```

### 1.4 Card Vendor Detection (1-2 days)
```kotlin
class EmvCardAnalyzer {
    fun detectVendor(aid: String): CardVendor
    fun getSupportedFeatures(vendor: CardVendor): Set<EmvFeature>
}
```

## Phase 2: Selective Crypto Porting (5-7 days) 
**What:** Port only heavy crypto operations from Proxmark3 C code

### 2.1 RSA Operations (2-3 days)
- Certificate validation
- Public key recovery  
- Signature verification

### 2.2 ROCA Detection (1-2 days)  
- Port emv_roca.c functionality
- Vulnerability scanning API

### 2.3 Advanced PKI (2-3 days)
- Certificate chain validation
- SDA/DDA/CDA authentication

## Phase 3: Integration & Testing (3-5 days)
**What:** Integrate Kotlin engine with NFC providers

### 3.1 NFC Integration
```kotlin
// Direct integration - no JNI for APDU traffic!
suspend fun processCard(tag: Tag): EmvResult {
    val provider = AndroidInternalNfcProvider()
    provider.connectToCard(parseTagToCardInfo(tag))
    
    return EmvTransactionEngine().processCard(provider)
}
```

### 3.2 Performance Testing
- Measure transaction times
- Profile memory usage  
- Validate against real cards

## Phase 4: Validation & Optimization (3-5 days)
- EMV compliance testing
- Performance optimization
- Security validation

## Phase 5: Polish & Release (2-3 days)  
- Demo application
- Documentation
- Release preparation

---

## Performance Comparison

### JNI Approach (Original Plan):
- Transaction time: 250-300ms (50ms JNI overhead)
- Memory usage: High (constant marshalling)
- Development time: 25-40 days
- Debugging difficulty: High (C + Kotlin)

### Hybrid Approach (Recommended):
- Transaction time: 200-250ms (5ms crypto JNI only)  
- Memory usage: Low (minimal marshalling)
- Development time: 20-30 days
- Debugging difficulty: Low (mostly Kotlin)

---

## Code Reuse Strategy

### From Proxmark3 (Reference Only):
- EMV transaction flows
- TLV tag definitions  
- Card vendor identification
- Authentication algorithms

### Direct Port (C → JNI):
- RSA cryptographic functions
- Certificate validation algorithms
- ROCA vulnerability detection
- Complex mathematical operations

### Kotlin Implementation (New):
- TLV parsing and manipulation
- APDU construction and parsing
- Transaction state management
- NFC communication handling
- Configuration and error handling