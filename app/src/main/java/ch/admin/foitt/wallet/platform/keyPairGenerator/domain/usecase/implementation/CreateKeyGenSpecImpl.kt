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
