package ch.admin.foitt.openid4vc.domain.usecase

import ch.admin.foitt.openid4vc.domain.model.GetSoftwareKeyPairError
import ch.admin.foitt.openid4vc.domain.model.SigningAlgorithm
import com.github.michaelbull.result.Result
import java.security.KeyPair

fun interface GetSoftwareKeyPair {
    suspend operator fun invoke(
        algorithm: SigningAlgorithm,
        publicKeyBytes: ByteArray,
        privateKeyBytes: ByteArray,
    ): Result<KeyPair, GetSoftwareKeyPairError>
}
