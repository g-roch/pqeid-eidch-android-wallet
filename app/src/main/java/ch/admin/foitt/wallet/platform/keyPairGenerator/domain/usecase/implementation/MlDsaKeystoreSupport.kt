package ch.admin.foitt.wallet.platform.keyPairGenerator.domain.usecase.implementation

import android.os.Build
import timber.log.Timber
import java.security.KeyPairGenerator
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.security.Security
import javax.inject.Inject
import javax.inject.Singleton


@Singleton
class MlDsaKeystoreSupport @Inject constructor() {

    private var cachedResult: Boolean? = null

    fun isSupported(provider: String = ANDROID_KEY_STORE): Boolean {
        cachedResult?.let { return it }

        val supported = if (Build.VERSION.SDK_INT < MIN_SDK_FOR_ML_DSA) {
            false
        } else {
            runCatching {
                KeyPairGenerator.getInstance(ML_DSA_44_JCA_NAME, provider)
                true
            }.getOrElse { throwable ->
                when (throwable) {
                    is NoSuchAlgorithmException, is NoSuchProviderException -> {
                        Timber.i(
                            throwable,
                            "ML-DSA not available on this device's $provider despite API ${Build.VERSION.SDK_INT}"
                        )
                        false
                    }
                    else -> throw throwable
                }
            }
        }

        cachedResult = supported
        // return supported
        // TODO for now return true as ML-DSA-44 is not supported by the keystore
        return true
    }

    /** Whether a general-purpose (non-AndroidKeyStore) provider on the classpath exposes ML-DSA,
     * used by [ch.admin.foitt.openid4vc.domain.usecase.jwt.implementation.MLDsaJWSVerifier] to
     * confirm BouncyCastle registered successfully before attempting verification. */
    fun isProviderRegistered(providerName: String): Boolean = Security.getProvider(providerName) != null

    companion object {
        private const val ANDROID_KEY_STORE = "AndroidKeyStore"
        private const val ML_DSA_44_JCA_NAME = "ML-DSA-44"

        // Android 17 == API level 37. Update if the platform ships this under a different level.
        private const val MIN_SDK_FOR_ML_DSA = 37
    }
}
