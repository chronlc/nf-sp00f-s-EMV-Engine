#include <jni.h>
#include <string>
#include <android/log.h>
#include <memory>
#include <vector>

// Include ported EMV headers
extern "C" {
    #include "proxmark_port/emvcore.h"
    #include "proxmark_port/tlv.h"
    #include "proxmark_port/emv_pki.h"
    #include "proxmark_port/emv_tags.h"
    #include "proxmark_port/crypto.h"
}

#define TAG "EMVPortJNI"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

// Global EMV state
static bool g_emv_initialized = false;

/**
 * Convert C string to Java string
 */
jstring stringToJString(JNIEnv* env, const char* str) {
    if (!str) return nullptr;
    return env->NewStringUTF(str);
}

/**
 * Convert Java byte array to C byte array
 */
std::vector<uint8_t> jbyteArrayToVector(JNIEnv* env, jbyteArray array) {
    std::vector<uint8_t> result;
    if (!array) return result;
    
    jsize length = env->GetArrayLength(array);
    jbyte* bytes = env->GetByteArrayElements(array, nullptr);
    
    result.assign(reinterpret_cast<uint8_t*>(bytes), 
                  reinterpret_cast<uint8_t*>(bytes) + length);
    
    env->ReleaseByteArrayElements(array, bytes, JNI_ABORT);
    return result;
}

/**
 * Convert C byte array to Java byte array
 */
jbyteArray vectorToJByteArray(JNIEnv* env, const std::vector<uint8_t>& data) {
    jbyteArray result = env->NewByteArray(static_cast<jsize>(data.size()));
    if (result) {
        env->SetByteArrayRegion(result, 0, static_cast<jsize>(data.size()), 
                               reinterpret_cast<const jbyte*>(data.data()));
    }
    return result;
}

/**
 * Create EMV transaction result object
 */
jobject createTransactionResult(JNIEnv* env, int status, const char* errorMsg) {
    // Find the EmvTransactionResult class
    jclass resultClass = env->FindClass("com/nf_sp00f/app/emv/EmvTransactionResult");
    if (!resultClass) {
        LOGE("Could not find EmvTransactionResult class");
        return nullptr;
    }
    
    // Find the constructor
    jmethodID constructor = env->GetMethodID(resultClass, "<init>", 
        "(Lcom/nf_sp00f/app/emv/EmvTransactionStatus;"
        "Lcom/nf_sp00f/app/emv/EmvTransactionType;"
        "Lcom/nf_sp00f/app/emv/EmvCardVendor;"
        "Ljava/lang/String;"  // applicationId
        "Ljava/lang/String;"  // cardholderName  
        "Ljava/lang/String;"  // pan
        "Ljava/lang/String;"  // expiryDate
        "Ljava/lang/String;"  // applicationLabel
        "Ljava/lang/String;"  // issuerCountryCode
        "Ljava/lang/String;"  // currencyCode
        "Ljava/lang/Long;"    // amount
        "Ljava/util/List;"    // authenticationMethods
        "Ljava/util/List;"    // certificates
        "Ljava/util/Map;"     // tlvData
        "Ljava/lang/String;"  // errorMessage
        ")V");
    
    if (!constructor) {
        LOGE("Could not find EmvTransactionResult constructor");
        return nullptr;
    }
    
    // Create status enum
    jclass statusClass = env->FindClass("com/nf_sp00f/app/emv/EmvTransactionStatus");
    jfieldID statusField = nullptr;
    
    switch (status) {
        case 0: // SUCCESS
            statusField = env->GetStaticFieldID(statusClass, "SUCCESS", 
                "Lcom/nf_sp00f/app/emv/EmvTransactionStatus;");
            break;
        case 1: // CARD_ERROR
            statusField = env->GetStaticFieldID(statusClass, "CARD_ERROR", 
                "Lcom/nf_sp00f/app/emv/EmvTransactionStatus;");
            break;
        default:
            statusField = env->GetStaticFieldID(statusClass, "UNKNOWN_ERROR", 
                "Lcom/nf_sp00f/app/emv/EmvTransactionStatus;");
    }
    
    jobject statusObj = env->GetStaticObjectField(statusClass, statusField);
    
    // Create empty lists and maps for now
    jclass arrayListClass = env->FindClass("java/util/ArrayList");
    jmethodID arrayListConstructor = env->GetMethodID(arrayListClass, "<init>", "()V");
    jobject emptyList = env->NewObject(arrayListClass, arrayListConstructor);
    
    jclass hashMapClass = env->FindClass("java/util/HashMap");
    jmethodID hashMapConstructor = env->GetMethodID(hashMapClass, "<init>", "()V");
    jobject emptyMap = env->NewObject(hashMapClass, hashMapConstructor);
    
    // Create the result object
    return env->NewObject(resultClass, constructor,
        statusObj,           // status
        nullptr,            // transactionType
        nullptr,            // cardVendor  
        nullptr,            // applicationId
        nullptr,            // cardholderName
        nullptr,            // pan
        nullptr,            // expiryDate
        nullptr,            // applicationLabel
        nullptr,            // issuerCountryCode
        nullptr,            // currencyCode
        nullptr,            // amount
        emptyList,          // authenticationMethods
        emptyList,          // certificates
        emptyMap,           // tlvData
        errorMsg ? stringToJString(env, errorMsg) : nullptr  // errorMessage
    );
}

extern "C" {

/**
 * Initialize EMV engine
 */
JNIEXPORT jboolean JNICALL
Java_com_nf_1sp00f_app_emv_EmvEngine_nativeInitializeEmv(JNIEnv *env, jobject thiz) {
    LOGD("Initializing EMV engine");
    
    try {
        // Initialize EMV subsystems
        // Note: Original Proxmark code doesn't have explicit init, 
        // but we may need to initialize crypto backends, etc.
        g_emv_initialized = true;
        
        LOGI("EMV engine initialized successfully");
        return JNI_TRUE;
        
    } catch (const std::exception& e) {
        LOGE("Failed to initialize EMV engine: %s", e.what());
        return JNI_FALSE;
    }
}

/**
 * Cleanup EMV engine
 */
JNIEXPORT void JNICALL
Java_com_nf_1sp00f_app_emv_EmvEngine_nativeCleanupEmv(JNIEnv *env, jobject thiz) {
    LOGD("Cleaning up EMV engine");
    g_emv_initialized = false;
}

/**
 * Process EMV card data
 */
JNIEXPORT jobject JNICALL
Java_com_nf_1sp00f_app_emv_EmvEngine_nativeProcessCard(JNIEnv *env, jobject thiz, 
                                                       jbyteArray cardData, jstring selectAid) {
    LOGD("Processing EMV card");
    
    if (!g_emv_initialized) {
        LOGE("EMV engine not initialized");
        return createTransactionResult(env, 1, "EMV engine not initialized");
    }
    
    try {
        // Convert input parameters
        auto cardBytes = jbyteArrayToVector(env, cardData);
        
        const char* aidStr = nullptr;
        if (selectAid) {
            aidStr = env->GetStringUTFChars(selectAid, nullptr);
        }
        
        LOGD("Processing card with %zu bytes of data", cardBytes.size());
        
        // TODO: Implement actual EMV processing using ported library
        // For now, return success status
        
        if (aidStr) {
            env->ReleaseStringUTFChars(selectAid, aidStr);
        }
        
        return createTransactionResult(env, 0, nullptr); // Success
        
    } catch (const std::exception& e) {
        LOGE("Error processing card: %s", e.what());
        return createTransactionResult(env, 1, e.what());
    }
}

/**
 * Get supported AIDs
 */
JNIEXPORT jobjectArray JNICALL
Java_com_nf_1sp00f_app_emv_EmvEngine_nativeGetSupportedAids(JNIEnv *env, jobject thiz) {
    LOGD("Getting supported AIDs");
    
    // Hardcoded list for now - will be expanded with actual EMV data
    std::vector<std::string> aids = {
        "A0000000031010",     // VISA
        "A0000000041010",     // MasterCard
        "A000000025010402",   // American Express
    };
    
    jclass stringClass = env->FindClass("java/lang/String");
    jobjectArray result = env->NewObjectArray(static_cast<jsize>(aids.size()), 
                                            stringClass, nullptr);
    
    for (size_t i = 0; i < aids.size(); i++) {
        jstring aidStr = stringToJString(env, aids[i].c_str());
        env->SetObjectArrayElement(result, static_cast<jsize>(i), aidStr);
        env->DeleteLocalRef(aidStr);
    }
    
    return result;
}

/**
 * Validate EMV certificate
 */
JNIEXPORT jboolean JNICALL
Java_com_nf_1sp00f_app_emv_EmvEngine_nativeValidateCertificate(JNIEnv *env, jobject thiz,
                                                              jbyteArray certData, 
                                                              jbyteArray issuerCert) {
    LOGD("Validating EMV certificate");
    
    if (!g_emv_initialized) {
        LOGE("EMV engine not initialized");
        return JNI_FALSE;
    }
    
    try {
        auto cert = jbyteArrayToVector(env, certData);
        auto issuer = jbyteArrayToVector(env, issuerCert);
        
        LOGD("Validating certificate with %zu bytes", cert.size());
        
        // TODO: Implement actual certificate validation using EMV PKI
        
        return JNI_TRUE; // Placeholder
        
    } catch (const std::exception& e) {
        LOGE("Error validating certificate: %s", e.what());
        return JNI_FALSE;
    }
}

} // extern "C"