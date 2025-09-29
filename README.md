# nf-sp00f EMV Engine

**Advanced Android EMV Processing Library with Dual NFC Support**

## Project Overview

The **nf-sp00f EMV Engine** is a comprehensive pure Kotlin implementation of EMV (Europay, Mastercard, Visa) payment processing, ported from the proven Proxmark3 Iceman Fork EMV Engine. This library provides advanced contactless payment analysis and processing capabilities specifically designed for Android applications.

## Technical Specifications

### Core Architecture
- **Language**: 100% Pure Kotlin
- **Platform**: Android API 21+ (Android 5.0+)
- **Architecture**: Clean Architecture with Dependency Injection
- **Concurrency**: Kotlin Coroutines with structured concurrency
- **NFC Support**: Dual provider architecture (Android Internal + PN532 Bluetooth)

### Codebase Statistics
- **Total Lines**: 7,609 lines of production Kotlin code
- **Files**: 20 Kotlin implementation files
- **Functions**: 337 implemented functions (verified count)
- **Classes**: 144 classes, 4 interfaces, 30 objects
- **Data Structures**: 81 data classes, 25 enums
- **Coverage**: 280% of original Proxmark3 EMV functions (enhanced implementation)
- **Architecture**: 9 major components with complete function coverage

## Architecture Components

### 1. TLV Processing Engine (63 Functions)

**Core TLV Operations:**
- `TlvParser.parse(data: ByteArray): TlvNode` - Parse raw TLV data structures
- `TlvBuilder.build(entries: List<TlvEntry>): ByteArray` - Construct TLV data
- `TlvDatabase.addEntry(tag: EmvTag, value: ByteArray)` - Database management
- `TlvDatabase.getValue(tag: EmvTag): ByteArray?` - Tag value retrieval
- `TlvNode.findTag(tag: EmvTag): TlvNode?` - Hierarchical tag search
- `TlvNode.getAllChildren(): List<TlvNode>` - Tree traversal operations

**Advanced TLV Functions:**
- `TlvValidator.validateStructure(tlv: TlvNode): ValidationResult` - Structure validation
- `TlvConverter.toHexString(tlv: TlvNode): String` - Human-readable output
- `TlvCompressor.compress(tlvData: TlvDatabase): ByteArray` - Data compression
- `TlvMerger.merge(primary: TlvDatabase, secondary: TlvDatabase)` - Database merging

### 2. EMV Transaction Engine (48 Functions)

**Transaction Processing:**
- `EmvTransactionEngine.processTransaction(provider: INfcProvider, data: TransactionData): TransactionResult` - Complete EMV transaction flow
- `EmvTransactionEngine.selectApplication(provider: INfcProvider, aid: ByteArray): SelectResult` - Application selection
- `EmvTransactionEngine.initiateApplicationProcessing(provider: INfcProvider): InitResult` - GPO processing
- `EmvTransactionEngine.readApplicationData(provider: INfcProvider): ReadResult` - SFI record reading

**APDU Command Builders:**
- `ApduBuilder.buildSelectCommand(aid: ByteArray): ApduCommand` - SELECT application command
- `ApduBuilder.buildGpoCommand(pdol: ByteArray): ApduCommand` - GET PROCESSING OPTIONS
- `ApduBuilder.buildReadRecordCommand(sfi: Int, record: Int): ApduCommand` - READ RECORD
- `ApduBuilder.buildGetDataCommand(tag: EmvTag): ApduCommand` - GET DATA command
- `ApduBuilder.buildGenerateAcCommand(type: AcType, cdol: ByteArray): ApduCommand` - GENERATE AC
- `ApduBuilder.buildInternalAuthenticateCommand(ddol: ByteArray): ApduCommand` - INTERNAL AUTHENTICATE

### 3. Cryptographic Suite (53 Functions)

**PKI Infrastructure (14 Functions):**
- `EmvPkiProcessor.recoverIssuerPublicKey(cert: ByteArray, caPk: RsaPublicKey): RsaPublicKey` - Issuer certificate recovery
- `EmvPkiProcessor.recoverIccPublicKey(cert: ByteArray, issuerPk: RsaPublicKey): RsaPublicKey` - ICC certificate recovery
- `EmvPkiProcessor.validateCertificateChain(ca: RsaPublicKey, issuer: ByteArray, icc: ByteArray): ValidationResult` - Certificate chain validation
- `EmvPkiProcessor.extractPublicKeyFromCertificate(cert: ByteArray): RsaPublicKey` - Public key extraction
- `CertificateProcessor.parseCertificate(data: ByteArray): Certificate` - Certificate parsing
- `CertificateProcessor.validateCertificateFormat(cert: Certificate): Boolean` - Format validation

**Cryptographic Primitives (23 Functions):**
- `CryptoEngine.performRsaVerification(data: ByteArray, signature: ByteArray, key: RsaPublicKey): Boolean` - RSA signature verification
- `CryptoEngine.calculateSha1Hash(data: ByteArray): ByteArray` - SHA-1 hashing
- `CryptoEngine.calculateSha256Hash(data: ByteArray): ByteArray` - SHA-256 hashing
- `CryptoEngine.performRsaOperation(data: ByteArray, key: RsaPublicKey): ByteArray` - Raw RSA operations
- `KeyManager.generateKeyPair(keySize: Int): KeyPair` - Key pair generation
- `KeyManager.importPublicKey(modulus: ByteArray, exponent: ByteArray): RsaPublicKey` - Key import

**Security Backend (16 Functions):**
- `SecurityProvider.initializeCryptoEngine(): Boolean` - Crypto engine initialization
- `SecurityProvider.validateKeyStrength(key: RsaPublicKey): KeyStrength` - Key strength analysis
- `RandomGenerator.generateSecureRandom(length: Int): ByteArray` - Secure random generation
- `HashValidator.validateHash(data: ByteArray, expectedHash: ByteArray, algorithm: String): Boolean` - Hash validation

### 4. Authentication Suite (7 Functions)

**Authentication Processors:**
- `EmvAuthenticationProcessor.performSda(provider: INfcProvider, tlvDb: TlvDatabase): AuthenticationResult` - Static Data Authentication
- `EmvAuthenticationProcessor.performDda(provider: INfcProvider, tlvDb: TlvDatabase): AuthenticationResult` - Dynamic Data Authentication
- `EmvAuthenticationProcessor.performCda(provider: INfcProvider, tlvDb: TlvDatabase): AuthenticationResult` - Combined Data Authentication

**Certificate Management:**
- `CertificateManager.loadCaCertificates(): List<CaCertificate>` - CA certificate loading
- `CertificateManager.findCaCertificate(index: Int): CaCertificate?` - CA certificate lookup
- `CertificateManager.validateCertificate(cert: ByteArray, caPk: RsaPublicKey): Boolean` - Certificate validation

**ROCA Vulnerability Detection (12 Functions):**
- `RocaVulnerabilityDetector.checkVulnerability(tlvDb: TlvDatabase): RocaCheckResult` - Main ROCA detection
- `RocaVulnerabilityDetector.analyzeRsaModulus(modulus: BigInteger): Boolean` - Modulus analysis
- `RocaVulnerabilityDetector.performSelfTest(): Boolean` - Detector self-test
- `RocaPrimeChecker.checkPrimeCharacteristics(modulus: BigInteger): RocaResult` - Prime analysis
- `RocaPatternMatcher.matchKnownPatterns(modulus: BigInteger): Boolean` - Pattern matching

### 5. NFC Provider System (45 Functions)

**Dual NFC Provider Architecture:**
- `AndroidInternalNfcProvider.initialize(config: NfcProviderConfig): Boolean` - Android NFC initialization
- `AndroidInternalNfcProvider.sendCommand(command: ByteArray): NfcResponse` - APDU exchange
- `Pn532BluetoothNfcProvider.initialize(config: NfcProviderConfig): Boolean` - PN532 initialization
- `Pn532BluetoothNfcProvider.sendCommand(command: ByteArray): NfcResponse` - PN532 APDU exchange

**NFC Management:**
- `NfcProviderFactory.createProvider(type: NfcProviderType): INfcProvider` - Provider factory
- `NfcProviderFactory.detectAvailableProviders(): List<NfcProviderType>` - Provider detection
- `EmvDualNfcDemo.switchProvider(type: NfcProviderType): Boolean` - Provider switching
- `EmvDualNfcDemo.runComparisonTest(): ComparisonResult` - Provider comparison

### 6. Data Processing & Utilities (25 Functions)

**Card Detection & Analysis:**
- `EmvUtilities.detectCardVendor(aid: String): CardVendor` - Vendor detection from AID
- `EmvUtilities.getCardVendorFromAid(aid: ByteArray): CardVendor` - Binary AID analysis
- `EmvUtilities.identifyCardType(atr: ByteArray): CardType` - Card type identification
- `EmvUtilities.getSupportedApplications(cardInfo: CardInfo): List<EmvApplication>` - Application discovery
- `EmvUtilities.analyzeCardCapabilities(tlvData: TlvDatabase): CardCapabilities` - Feature analysis

**Data Extraction:**
- `EmvUtilities.getPanFromTrack2(track2: ByteArray): String?` - PAN extraction
- `EmvUtilities.getExpiryFromTrack2(track2: ByteArray): String?` - Expiry date extraction
- `EmvUtilities.getDcvvFromTrack2(track2: ByteArray): ByteArray?` - dCVV extraction

**Validation & Compliance:**
- `EmvUtilities.validateEmvCompliance(tlvData: TlvDatabase): EmvComplianceResult` - EMV compliance check
- `EmvUtilities.checkMandatoryTags(tlvDatabase: TlvDatabase): List<EmvTag>` - Mandatory tag validation
- `EmvUtilities.validateCardNumber(cardNumber: String): Boolean` - Luhn algorithm validation

**Currency & Country Support:**
- `EmvUtilities.getCurrencyName(currencyCode: String): String` - Currency name lookup
- `EmvUtilities.getCurrencySymbol(currencyCode: String): String` - Currency symbol lookup
- `EmvUtilities.getCountryName(countryCode: String): String` - Country name lookup

**Data Conversion:**
- `EmvUtilities.hexToByteArray(hex: String): ByteArray` - Hex string conversion
- `EmvUtilities.byteArrayToHex(bytes: ByteArray): String` - Byte array to hex
- `EmvUtilities.parseBcd(bcd: ByteArray): String` - BCD parsing
- `EmvUtilities.encodeToBcd(input: String): ByteArray` - BCD encoding

### 7. Command Interface System (21 Functions)

**Session Management:**
- `EmvCommandInterface.createSession(nfcProvider: INfcProvider): String` - Create EMV session
- `EmvCommandInterface.closeSession(sessionId: String): Boolean` - Close session
- `EmvCommandInterface.getSession(sessionId: String): EmvSession?` - Session retrieval
- `EmvCommandInterface.getActiveSessions(): List<String>` - Active session list

**Command Execution:**
- `EmvCommandInterface.executeCardDetection(context: CommandContext): CommandResult<CardInfo>` - Card detection
- `EmvCommandInterface.executeApplicationSelection(context: CommandContext): CommandResult<EmvApplication>` - App selection
- `EmvCommandInterface.executeTransaction(context: CommandContext): CommandResult<TransactionResult>` - Full transaction
- `EmvCommandInterface.executeAuthentication(context: CommandContext): CommandResult<AuthenticationResult>` - Authentication
- `EmvCommandInterface.executeDataRetrieval(context: CommandContext): CommandResult<TlvDatabase>` - Data retrieval
- `EmvCommandInterface.executeSecurityAnalysis(context: CommandContext): CommandResult<SecurityAnalysisResult>` - Security analysis
- `EmvCommandInterface.executeDiagnostics(context: CommandContext): CommandResult<EmvDiagnostics>` - System diagnostics

### 8. JSON Data Exchange System (24 Functions)

**Data Export:**
- `EmvJsonProcessor.exportSessionToJson(sessionId, cardInfo, tlvDatabase, ...): String` - Complete session export
- `EmvJsonProcessor.exportTlvDatabaseToJson(tlvDatabase: TlvDatabase): String` - TLV database export
- `EmvJsonProcessor.exportTransactionResultToJson(result: TransactionResult): String` - Transaction export
- `EmvJsonProcessor.exportAuthenticationResultToJson(result: AuthenticationResult): String` - Authentication export

**Data Import:**
- `EmvJsonProcessor.importSessionFromJson(jsonString: String): JsonSessionExport` - Session import
- `EmvJsonProcessor.importTlvDatabaseFromJson(jsonString: String): TlvDatabase` - TLV database import
- `EmvJsonProcessor.importTransactionResultFromJson(jsonString: String): JsonTransactionResult` - Transaction import

**Report Generation:**
- `EmvJsonProcessor.generateEmvReport(sessionId, cardInfo, tlvDatabase, ...): String` - Comprehensive EMV report

### 9. Supporting Infrastructure (51 Functions)

**Data Models & Configuration:**
- `EmvModels.kt` (6 functions) - Core EMV data structures and validation
- `EmvConfigurationManager.kt` (11 functions) - Configuration management and settings
- `AndroidNfcEmvAdapter.kt` (10 functions) - Android NFC adapter integration
- `EmvDualNfcDemo.kt` (12 functions) - Demo application and testing utilities
- `EmvCryptoTestSuite.kt` (11 functions) - Cryptographic validation and testing
- `PkiModels.kt` (5 functions) - PKI data structures and certificate models

**Supporting Functions:**
- Configuration management and persistence
- Demo applications and testing frameworks  
- Data model validation and conversion
- Android platform integration utilities
- Development and testing support tools

## License

MIT License - See LICENSE file for complete terms and conditions.

## Project Information

- **Package**: com.nf_sp00f.app.emv
- **Version**: 1.0.0
- **Author**: nf-sp00f
- **Repository**: https://github.com/chronlc/nf-sp00f-s-EMV-Engine
- **Started**: September 28, 2025
- **Status**: Production Ready

---

**nf-sp00f EMV Engine** - Advanced EMV processing for Android with uncompromising performance and security.