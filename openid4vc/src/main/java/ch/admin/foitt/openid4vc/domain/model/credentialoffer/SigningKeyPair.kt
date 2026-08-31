package ch.admin.foitt.openid4vc.domain.model.credentialoffer

import ch.admin.foitt.openid4vc.domain.model.SigningAlgorithm
import ch.admin.foitt.openid4vc.domain.model.KeyExchangeAlgorithm
import ch.admin.foitt.openid4vc.domain.model.keyBinding.KeyBindingType
import java.security.KeyPair
import com.nimbusds.jose.jwk.XWingKey

interface SigningKeyPair {
    val keyPair: KeyPair
    val keyId: String
}

data class JWSKeyPair(
    val algorithm: SigningAlgorithm,
    override val keyPair: KeyPair,
    override val keyId: String,
    val bindingType: KeyBindingType,
) : SigningKeyPair

/**
 * Key pair used for response payload encryption.
 *
 * X-Wing keys have no JCA [KeyPair]/[java.security.PrivateKey] representation
 * (BouncyCastle only exposes the lightweight `org.bouncycastle.pqc.crypto.xwing`
 * API), so the raw [XWingKey] JWK is kept directly - it is what
 * [com.nimbusds.jose.crypto.XWingEncrypter]/[com.nimbusds.jose.crypto.XWingDecrypter]
 * consume.
 */
data class JWEKeyPair(
    val algorithm: KeyExchangeAlgorithm,
    val jwk: XWingKey,
    val keyId: String,
    val bindingType: KeyBindingType,
)
