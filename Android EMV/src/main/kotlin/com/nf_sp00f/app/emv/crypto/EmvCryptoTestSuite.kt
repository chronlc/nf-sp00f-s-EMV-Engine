/**
 * nf-sp00f EMV Engine - Crypto Test Suite
 * 
 * Comprehensive testing for cryptographic primitives and ROCA detection.
 * Validates implementation against known test vectors.
 * 
 * @package com.nf_sp00f.app.emv.crypto
 * @author nf-sp00f
 * @since 1.0.0
 */
package com.nf_sp00f.app.emv.crypto

import com.nf_sp00f.app.emv.security.RocaSecurityScanner
import com.nf_sp00f.app.emv.security.RocaDetectionMethod
import kotlinx.coroutines.*
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.interfaces.RSAPublicKey
import java.math.BigInteger

/**
 * Comprehensive crypto test suite
 */
class EmvCryptoTestSuite {
    
    companion object {
        private const val TAG = "EmvCryptoTestSuite"
        
        // Test vectors for hash algorithms
        private val SHA1_TEST_VECTOR = "abc" to "a9993e364706816aba3e25717850c26c9cd0d89d"
        private val SHA256_TEST_VECTOR = "abc" to "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    }
    
    private val rocaScanner = RocaSecurityScanner()
    private val cryptoPrimitives = EmvCryptoPrimitives()
    
    /**
     * Run complete crypto test suite
     */
    suspend fun runAllTests(): CryptoTestResult = withContext(Dispatchers.Default) {
        val results = mutableListOf<TestCase>()
        
        try {
            // Test 1: Crypto primitives initialization
            results.add(testCryptoPrimitivesInit())
            
            // Test 2: Hash algorithm tests
            results.add(testHashAlgorithms())
            
            // Test 3: RSA operations
            results.add(testRsaOperations())
            
            // Test 4: ROCA detection
            results.add(testRocaDetection())
            
            // Test 5: ROCA self-test
            results.add(testRocaSelfTest())
            
            // Test 6: Key generation and validation
            results.add(testKeyGeneration())
            
            // Test 7: Crypto utilities
            results.add(testCryptoUtilities())
            
            val passed = results.count { it.passed }
            val total = results.size
            
            CryptoTestResult(
                passed = passed == total,
                totalTests = total,
                passedTests = passed,
                failedTests = total - passed,
                testCases = results,
                summary = "Crypto Test Suite: $passed/$total tests passed"
            )
            
        } catch (e: Exception) {
            CryptoTestResult(
                passed = false,
                totalTests = 1,
                passedTests = 0,
                failedTests = 1,
                testCases = listOf(
                    TestCase(
                        name = "Test Suite Execution",
                        passed = false,
                        details = "Test suite failed with exception: ${e.message}"
                    )
                ),
                summary = "Test suite execution failed"
            )
        }
    }
    
    /**
     * Test crypto primitives initialization
     */
    private suspend fun testCryptoPrimitivesInit(): TestCase {
        return try {
            val initialized = cryptoPrimitives.initialize()
            val backendInfo = cryptoPrimitives.getBackendInfo()
            
            TestCase(
                name = "Crypto Primitives Initialization",
                passed = initialized,
                details = if (initialized) {
                    "Successfully initialized crypto primitives: $backendInfo"
                } else {
                    "Failed to initialize crypto primitives"
                }
            )
        } catch (e: Exception) {
            TestCase(
                name = "Crypto Primitives Initialization",
                passed = false,
                details = "Exception during initialization: ${e.message}"
            )
        }
    }
    
    /**
     * Test hash algorithms with known test vectors
     */
    private suspend fun testHashAlgorithms(): TestCase {
        return try {
            val results = mutableListOf<String>()
            
            // Test SHA-1
            val sha1Hash = EmvCryptoUtils.sha1Hash(SHA1_TEST_VECTOR.first.toByteArray())
            val sha1Hex = EmvCryptoUtils.bytesToHex(sha1Hash).lowercase()
            val sha1Passed = sha1Hex == SHA1_TEST_VECTOR.second
            results.add("SHA-1: ${if (sha1Passed) "PASS" else "FAIL"} ($sha1Hex)")
            
            // Test SHA-256
            val sha256Hash = EmvCryptoUtils.sha256Hash(SHA256_TEST_VECTOR.first.toByteArray())
            val sha256Hex = EmvCryptoUtils.bytesToHex(sha256Hash).lowercase()
            val sha256Passed = sha256Hex == SHA256_TEST_VECTOR.second
            results.add("SHA-256: ${if (sha256Passed) "PASS" else "FAIL"} ($sha256Hex)")
            
            // Test multi-hash
            val multiHash = EmvCryptoUtils.multiHash(
                HashAlgorithm.SHA1,
                "Hello".toByteArray(),
                " ".toByteArray(),
                "World".toByteArray()
            )
            val multiHashPassed = multiHash.isNotEmpty()
            results.add("Multi-hash: ${if (multiHashPassed) "PASS" else "FAIL"}")
            
            val allPassed = sha1Passed && sha256Passed && multiHashPassed
            
            TestCase(
                name = "Hash Algorithms",
                passed = allPassed,
                details = results.joinToString("; ")
            )
            
        } catch (e: Exception) {
            TestCase(
                name = "Hash Algorithms",
                passed = false,
                details = "Hash test failed: ${e.message}"
            )
        }
    }
    
    /**
     * Test RSA operations
     */
    private suspend fun testRsaOperations(): TestCase {
        return try {
            val results = mutableListOf<String>()
            
            // Generate test key pair
            val keyGenerator = KeyPairGenerator.getInstance("RSA")
            keyGenerator.initialize(1024, SecureRandom())
            val keyPair = keyGenerator.generateKeyPair()
            results.add("Key generation: PASS")
            
            // Test key validation
            val rsaPublicKey = keyPair.public as RSAPublicKey
            val modulus = rsaPublicKey.modulus.toByteArray()
            val exponent = rsaPublicKey.publicExponent.toByteArray()
            val keyValid = EmvCryptoUtils.validateRsaKey(modulus, exponent)
            results.add("Key validation: ${if (keyValid) "PASS" else "FAIL"}")
            
            // Test random generation
            val randomBytes1 = EmvCryptoUtils.generateRandomBytes(32)
            val randomBytes2 = EmvCryptoUtils.generateRandomBytes(32)
            val randomWorked = randomBytes1.size == 32 && !randomBytes1.contentEquals(randomBytes2)
            results.add("Random generation: ${if (randomWorked) "PASS" else "FAIL"}")
            
            val allPassed = keyValid && randomWorked
            
            TestCase(
                name = "RSA Operations",
                passed = allPassed,
                details = results.joinToString("; ")
            )
            
        } catch (e: Exception) {
            TestCase(
                name = "RSA Operations",
                passed = false,
                details = "RSA test failed: ${e.message}"
            )
        }
    }
    
    /**
     * Test ROCA detection capabilities
     */
    private suspend fun testRocaDetection(): TestCase {
        return try {
            val results = mutableListOf<String>()
            
            // Generate a normal (non-vulnerable) key
            val keyGenerator = KeyPairGenerator.getInstance("RSA")
            keyGenerator.initialize(1024, SecureRandom())
            val normalKey = keyGenerator.generateKeyPair().public as RSAPublicKey
            
            // Test normal key (should not be vulnerable)
            val normalResult = rocaScanner.checkRocaVulnerability(
                normalKey,
                RocaDetectionMethod.FINGERPRINT_ANALYSIS
            )
            val normalTestPassed = !normalResult.isVulnerable
            results.add("Normal key test: ${if (normalTestPassed) "PASS" else "FAIL"} (confidence: ${String.format("%.2f", normalResult.confidence * 100)}%)")
            
            // Test different detection methods
            val modulusResult = rocaScanner.checkRocaVulnerability(
                normalKey,
                RocaDetectionMethod.MODULUS_ANALYSIS
            )
            val modulusTestPassed = modulusResult.analysisMethod == RocaDetectionMethod.MODULUS_ANALYSIS
            results.add("Modulus analysis: ${if (modulusTestPassed) "PASS" else "FAIL"}")
            
            val allPassed = normalTestPassed && modulusTestPassed
            
            TestCase(
                name = "ROCA Detection",
                passed = allPassed,
                details = results.joinToString("; ")
            )
            
        } catch (e: Exception) {
            TestCase(
                name = "ROCA Detection",
                passed = false,
                details = "ROCA detection test failed: ${e.message}"
            )
        }
    }
    
    /**
     * Test ROCA self-test functionality
     */
    private suspend fun testRocaSelfTest(): TestCase {
        return try {
            val selfTestPassed = rocaScanner.runSelfTest()
            
            TestCase(
                name = "ROCA Self-Test",
                passed = selfTestPassed,
                details = if (selfTestPassed) {
                    "ROCA self-test completed successfully"
                } else {
                    "ROCA self-test failed - detection algorithms may not be properly initialized"
                }
            )
            
        } catch (e: Exception) {
            TestCase(
                name = "ROCA Self-Test",
                passed = false,
                details = "ROCA self-test exception: ${e.message}"
            )
        }
    }
    
    /**
     * Test key generation and validation
     */
    private suspend fun testKeyGeneration(): TestCase {
        return try {
            val results = mutableListOf<String>()
            
            // Test different key sizes
            val keySizes = listOf(1024, 2048)
            
            for (keySize in keySizes) {
                val keyGenerator = KeyPairGenerator.getInstance("RSA")
                keyGenerator.initialize(keySize, SecureRandom())
                val keyPair = keyGenerator.generateKeyPair()
                val rsaKey = keyPair.public as RSAPublicKey
                val actualSize = rsaKey.modulus.bitLength()
                val sizeCorrect = actualSize >= keySize - 8 && actualSize <= keySize + 8 // Allow some variance
                results.add("${keySize}-bit key: ${if (sizeCorrect) "PASS" else "FAIL"} (actual: $actualSize)")
            }
            
            val allPassed = results.all { it.contains("PASS") }
            
            TestCase(
                name = "Key Generation",
                passed = allPassed,
                details = results.joinToString("; ")
            )
            
        } catch (e: Exception) {
            TestCase(
                name = "Key Generation",
                passed = false,
                details = "Key generation test failed: ${e.message}"
            )
        }
    }
    
    /**
     * Test crypto utilities
     */
    private suspend fun testCryptoUtilities(): TestCase {
        return try {
            val results = mutableListOf<String>()
            
            // Test hex conversion
            val testBytes = byteArrayOf(0x12, 0x34, 0xAB.toByte(), 0xCD.toByte())
            val hex = EmvCryptoUtils.bytesToHex(testBytes)
            val backToBytes = EmvCryptoUtils.hexToBytes(hex)
            val hexWorked = hex == "1234ABCD" && testBytes.contentEquals(backToBytes)
            results.add("Hex conversion: ${if (hexWorked) "PASS" else "FAIL"}")
            
            // Test constant-time comparison
            val array1 = byteArrayOf(1, 2, 3, 4)
            val array2 = byteArrayOf(1, 2, 3, 4)
            val array3 = byteArrayOf(1, 2, 3, 5)
            val compareWorked = EmvCryptoUtils.constantTimeEquals(array1, array2) && 
                               !EmvCryptoUtils.constantTimeEquals(array1, array3)
            results.add("Constant-time comparison: ${if (compareWorked) "PASS" else "FAIL"}")
            
            val allPassed = hexWorked && compareWorked
            
            TestCase(
                name = "Crypto Utilities",
                passed = allPassed,
                details = results.joinToString("; ")
            )
            
        } catch (e: Exception) {
            TestCase(
                name = "Crypto Utilities",
                passed = false,
                details = "Crypto utilities test failed: ${e.message}"
            )
        }
    }
    
    /**
     * Get ROCA information for testing
     */
    fun getRocaInfo(): String = rocaScanner.getRocaInfo()
    
    /**
     * Cleanup test resources
     */
    fun cleanup() {
        rocaScanner.cleanup()
        cryptoPrimitives.cleanup()
    }
}

/**
 * Test case result
 */
data class TestCase(
    val name: String,
    val passed: Boolean,
    val details: String
)

/**
 * Complete test result
 */
data class CryptoTestResult(
    val passed: Boolean,
    val totalTests: Int,
    val passedTests: Int,
    val failedTests: Int,
    val testCases: List<TestCase>,
    val summary: String
) {
    
    /**
     * Get detailed test report
     */
    fun getDetailedReport(): String {
        val builder = StringBuilder()
        
        builder.appendLine("=== nf-sp00f EMV Engine - Crypto Test Report ===")
        builder.appendLine(summary)
        builder.appendLine()
        
        for (testCase in testCases) {
            val status = if (testCase.passed) "✅ PASS" else "❌ FAIL"
            builder.appendLine("$status - ${testCase.name}")
            builder.appendLine("    Details: ${testCase.details}")
            builder.appendLine()
        }
        
        builder.appendLine("Overall Result: ${if (passed) "ALL TESTS PASSED" else "SOME TESTS FAILED"}")
        
        return builder.toString()
    }
}
