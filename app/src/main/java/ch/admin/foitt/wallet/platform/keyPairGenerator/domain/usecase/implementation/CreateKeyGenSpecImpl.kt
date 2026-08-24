package ch.admin.foitt.wallet.platform.keyPairGenerator.domain.usecase.implementation

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import ch.admin.foitt.openid4vc.domain.model.SigningAlgorithm
import ch.admin.foitt.wallet.platform.keyPairGenerator.domain.model.CreateKeyGenSpecError
import ch.admin.foitt.wallet.platform.keyPairGenerator.domain.model.toCreateKeyGenSpecError
import ch.admin.foitt.wallet.platform.keyPairGenerator.domain.usecase.CreateKeyGenSpec
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.coroutines.runSuspendCatching
import com.github.michaelbull.result.mapError
import javax.inject.Inject

class CreateKeyGenSpecImpl @Inject constructor() : CreateKeyGenSpec {
    override fun invoke(
        keyId: String,
        signingAlgorithm: SigningAlgorithm,
        useStrongBox: Boolean,
        attestationChallenge: ByteArray?,
    ): Result<KeyGenParameterSpec, CreateKeyGenSpecError> = runSuspendCatching {
        // ML-DSA-65 is a single, fully-specified parameter set — unlike EC there's no
        // curve/digest choice to make here. The algorithm name passed to
        // KeyPairGenerator.getInstance() (see CreateJWSKeyPairInHardwareImpl) fully determines
        // the key, so the builder only needs purpose, StrongBox preference, and the attestation
        // challenge.
        //
        // CAUTION: as of Android 17's initial release, StrongBox's documented algorithm set
        // (RSA-2048, AES, ECDSA/ECDH P-256, HMAC-SHA256, 3DES) does not list ML-DSA. Passing
        // useStrongBox = true here can still generate a spec fine, but the *later*
        // generateKeyPair() call (in CreateJWSKeyPairInHardwareImpl) throws
        // StrongBoxUnavailableException on devices whose StrongBox HAL hasn't added ML-DSA yet,
        // even if their TEE has — the fallback-and-retry has to live there, not in this builder.
        KeyGenParameterSpec.Builder(
            keyId,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
        )
            .setIsStrongBoxBacked(useStrongBox)
            .apply {
                if (attestationChallenge != null) {
                    setAttestationChallenge(attestationChallenge)
                }
            }
            .build()
    }.mapError { throwable ->
        throwable.toCreateKeyGenSpecError("Error creating key gen spec")
    }
}
