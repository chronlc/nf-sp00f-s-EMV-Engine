#include "nfc_adapter.h"
#include <android/log.h>

#define TAG "NFCAdapter"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

extern "C" {
    // Forward declarations for EMV core functions that need hardware abstraction
    #include "proxmark_port/emvcore.h"
    #include "proxmark_port/tlv.h"
}

/**
 * Android Internal NFC Adapter Implementation
 * 
 * This module provides a complete bridge between Proxmark3 EMV code and 
 * Android's internal NFC adapter. It handles all APDU exchanges through
 * Android's IsoDep interface, providing seamless EMV processing.
 */

// Global JNI references for callback to Kotlin layer
static JavaVM* g_jvm = nullptr;
static jclass g_nfc_adapter_class = nullptr;
static jmethodID g_transceive_method = nullptr;
static jobject g_nfc_adapter_instance = nullptr;

namespace AndroidNFC {

/**
 * Initialize JNI callbacks for Android NFC operations
 */
int InitializeAndroidNFC(JNIEnv* env, jobject nfcAdapterInstance) {
    LOGD("Initializing Android NFC adapter callbacks");
    
    // Get JavaVM reference
    if (env->GetJavaVM(&g_jvm) != JNI_OK) {
        LOGE("Failed to get JavaVM reference");
        return -1;
    }
    
    // Get NFC adapter class and methods
    jclass localClass = env->FindClass("com/nf_sp00f/app/emv/AndroidNfcEmvAdapter");
    if (!localClass) {
        LOGE("Failed to find AndroidNfcEmvAdapter class");
        return -1;
    }
    
    g_nfc_adapter_class = (jclass)env->NewGlobalRef(localClass);
    g_nfc_adapter_instance = env->NewGlobalRef(nfcAdapterInstance);
    
    // Get the exchangeApdu method
    g_transceive_method = env->GetMethodID(g_nfc_adapter_class, "exchangeApdu", 
                                          "([B)Lcom/nf_sp00f/app/emv/ApduResponse;");
    if (!g_transceive_method) {
        LOGE("Failed to find exchangeApdu method");
        return -1;
    }
    
    LOGD("Android NFC adapter initialized successfully");
    return 0;
}

/**
 * Replace Proxmark3's EMVExchange with Android internal NFC transceive
 */
int AndroidEMVExchange(void* nfcHandle, bool leaveFieldOn, 
                      const uint8_t* apdu, size_t apduLen,
                      uint8_t* response, size_t maxResponseLen, size_t* responseLen) {
    
    LOGD("AndroidEMVExchange: APDU length %zu", apduLen);
    
    if (!apdu || !response || !responseLen || !g_jvm) {
        LOGE("Invalid parameters for EMV exchange");
        return -1;
    }
    
    JNIEnv* env = nullptr;
    bool needDetach = false;
    
    // Get JNI environment
    int getEnvResult = g_jvm->GetEnv((void**)&env, JNI_VERSION_1_6);
    if (getEnvResult == JNI_EDETACHED) {
        if (g_jvm->AttachCurrentThread(&env, nullptr) != JNI_OK) {
            LOGE("Failed to attach thread to JVM");
            return -1;
        }
        needDetach = true;
    } else if (getEnvResult != JNI_OK) {
        LOGE("Failed to get JNI environment");
        return -1;
    }
    
    try {
        // Create Java byte array for APDU
        jbyteArray apduArray = env->NewByteArray(static_cast<jsize>(apduLen));
        env->SetByteArrayRegion(apduArray, 0, static_cast<jsize>(apduLen), 
                               reinterpret_cast<const jbyte*>(apdu));
        
        // Call Android NFC exchangeApdu method
        jobject responseObj = env->CallObjectMethod(g_nfc_adapter_instance, 
                                                   g_transceive_method, apduArray);
        
        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
            LOGE("Exception during APDU exchange");
            return -1;
        }
        
        if (!responseObj) {
            LOGE("Null response from APDU exchange");
            return -1;
        }
        
        // Get ApduResponse fields
        jclass responseClass = env->FindClass("com/nf_sp00f/app/emv/ApduResponse");
        jfieldID dataField = env->GetFieldID(responseClass, "data", "[B");
        jfieldID swField = env->GetFieldID(responseClass, "sw", "I");
        
        // Extract response data
        jbyteArray responseData = (jbyteArray)env->GetObjectField(responseObj, dataField);
        jint sw = env->GetIntField(responseObj, swField);
        
        // Copy response data
        jsize responseDataLen = env->GetArrayLength(responseData);
        if (responseDataLen + 2 > static_cast<jsize>(maxResponseLen)) {
            LOGE("Response too large for buffer");
            return -1;
        }
        
        jbyte* responseBytes = env->GetByteArrayElements(responseData, nullptr);
        memcpy(response, responseBytes, responseDataLen);
        
        // Add SW1 SW2 to response
        response[responseDataLen] = (sw >> 8) & 0xFF;
        response[responseDataLen + 1] = sw & 0xFF;
        
        *responseLen = responseDataLen + 2;
        
        env->ReleaseByteArrayElements(responseData, responseBytes, JNI_ABORT);
        env->DeleteLocalRef(apduArray);
        env->DeleteLocalRef(responseObj);
        
        LOGD("Android NFC exchange successful: %zu bytes", *responseLen);
        return 0;
        
    } catch (...) {
        LOGE("Exception in Android NFC exchange");
        return -1;
    } finally {
        if (needDetach) {
            g_jvm->DetachCurrentThread();
        }
    }
}

/**
 * Android field activation (replaces Proxmark3 field control)
 */
int AndroidActivateField(bool activate) {
    LOGD("AndroidActivateField: %s", activate ? "ON" : "OFF");
    
    // In Android NFC, field is automatically managed by the system
    // This is mostly a no-op but can be used for logging/state tracking
    
    return 0; // Success
}

/**
 * Android card detection and connection
 */
int AndroidConnectCard(void** cardHandle) {
    LOGD("AndroidConnectCard");
    
    // TODO: Implement Android NFC card connection
    // This will interface with the IsoDep connection from Kotlin
    
    if (!cardHandle) {
        LOGE("Invalid card handle pointer");
        return -1;
    }
    
    *cardHandle = nullptr; // Placeholder
    return 0; // Success
}

/**
 * Android card disconnection
 */
int AndroidDisconnectCard(void* cardHandle) {
    LOGD("AndroidDisconnectCard");
    
    // TODO: Implement Android NFC card disconnection
    // Close IsoDep connection
    
    return 0; // Success
}

} // namespace AndroidNFC

// C interface functions for the ported EMV library

extern "C" {

/**
 * Hardware abstraction layer - these functions replace Proxmark3 specific calls
 */

int android_emv_exchange_apdu(const uint8_t* apdu, size_t apdu_len, 
                             uint8_t* response, size_t max_resp_len, 
                             size_t* resp_len) {
    return AndroidNFC::AndroidEMVExchange(nullptr, false, apdu, apdu_len, 
                                         response, max_resp_len, resp_len);
}

int android_activate_field(bool activate) {
    return AndroidNFC::AndroidActivateField(activate);
}

int android_connect_card(void** handle) {
    return AndroidNFC::AndroidConnectCard(handle);
}

int android_disconnect_card(void* handle) {
    return AndroidNFC::AndroidDisconnectCard(handle);
}

} // extern "C"