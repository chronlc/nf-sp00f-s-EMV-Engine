# EMV Port Conversion Tracking

This directory tracks the conversion progress from Proxmark3 EMV C code to Android Kotlin library.

## Conversion Status

### ✅ Completed Files
- [ ] None yet - conversion in progress

### 🔄 In Progress  
- [ ] None currently active

### ⏳ Pending Conversion
- [ ] emvcore.c/h - Main EMV transaction engine
- [ ] tlv.c/h - TLV data structure handling  
- [ ] crypto.c/h - Cryptographic functions
- [ ] emv_pki.c/h - PKI certificate handling
- [ ] dol.c/h - Data Object List processing
- [ ] emv_tags.c/h - EMV tag definitions
- [ ] emvjson.c/h - JSON serialization
- [ ] emv_pk.c/h - Public key operations
- [✅] emv_roca.c/h - **ROCA vulnerability detection (CVE-2017-15361) - INCLUDED**
- [ ] crypto_polarssl.c - mbedTLS integration

### 🧪 Test Files
- [ ] test/crypto_test.c/h
- [ ] test/cda_test.c/h  
- [ ] test/dda_test.c/h
- [ ] test/sda_test.c/h
- [ ] test/cryptotest.c/h

## Conversion Strategy

1. **Phase 1**: Port core data structures (TLV, DOL)
2. **Phase 2**: Port cryptographic functions with Android backend
3. **Phase 3**: Port EMV transaction engine with NFC abstraction  
4. **Phase 4**: Port PKI and authentication methods
5. **Phase 5**: Port testing framework
6. **Phase 6**: Integration and optimization

## Security Features

### ✅ ROCA Vulnerability Detection (CVE-2017-15361)
- **Full Proxmark3 ROCA implementation included**
- RSA key fingerprint analysis
- Certificate scanning capabilities  
- Self-test verification
- Kotlin API wrapper with JNI bridge
- Detects vulnerable Infineon TPMs and smartcards

## Dependencies to Address

### External Libraries
- **jansson** → Replace with Kotlin JSON serialization
- **mbedtls** → Replace with Android crypto APIs or port subset
- **Proxmark3 UI/comms** → Replace with Android NFC APIs

### Hardware Abstraction
- **ISO7816 channels** → Android IsoDep  
- **APDU exchange** → IsoDep.transceive()
- **Field control** → Android NFC system management

### Memory Management  
- **malloc/free** → Careful JNI memory handling
- **Buffer management** → Android-safe memory operations

## Notes
- All files will be adapted to Android-compatible headers
- Hardware dependencies will be abstracted through nfc_adapter.h
- Threading will be handled at Kotlin coroutine level
- Error handling adapted for Android exception patterns