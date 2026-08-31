package ch.admin.foitt.wallet.platform.keybindingMatching.domain.usecase.implementation

import ch.admin.foitt.openid4vc.domain.model.jwk.Jwk
import ch.admin.foitt.openid4vc.domain.model.jwk.mlDsaPublicKeyToJwk
import ch.admin.foitt.openid4vc.domain.model.keyBinding.KeyBinding
import ch.admin.foitt.openid4vc.domain.model.keyBinding.KeyBindingType
import ch.admin.foitt.openid4vc.domain.model.sdjwt.SdJwt
import ch.admin.foitt.openid4vc.domain.usecase.GetHardwareKeyPair
import ch.admin.foitt.openid4vc.utils.Constants.ANDROID_KEY_STORE
import ch.admin.foitt.wallet.platform.appAttestation.domain.model.Confirmation
import ch.admin.foitt.wallet.platform.keybindingMatching.domain.model.MatchKeyBindingToPayloadCnfError
import ch.admin.foitt.wallet.platform.keybindingMatching.domain.model.toMatchKeyBindingToPayloadCnfError
import ch.admin.foitt.wallet.platform.keybindingMatching.domain.usecase.MatchKeyBindingToPayloadCnf
import ch.admin.foitt.wallet.platform.utils.JsonParsingError
import ch.admin.foitt.wallet.platform.utils.SafeJson
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.coroutines.coroutineBinding
import com.github.michaelbull.result.get
import com.github.michaelbull.result.mapError
import kotlinx.serialization.json.jsonObject
import javax.inject.Inject

class MatchKeyBindingToPayloadCnfImpl @Inject constructor(
    private val safeJson: SafeJson,
    private val getHardwareKeyPair: GetHardwareKeyPair,
) : MatchKeyBindingToPayloadCnf {
    override suspend fun invoke(
        keyBindings: List<KeyBinding?>,
        payload: String,
    ): Result<KeyBinding, MatchKeyBindingToPayloadCnfError> = coroutineBinding {
        val keyBindingJwkPairs = keyBindings.filterNotNull().mapNotNull { kb ->
            kb.toJwk()?.let { jwk -> kb to jwk }
        }

        val sdJwt = SdJwt(payload)
        val cnfJsonElement = sdJwt.processedJson.jsonObject["cnf"]
        val confirmation: Confirmation? = cnfJsonElement?.let {
            safeJson.safeDecodeFromJsonElement<Confirmation>(it)
                .mapError(JsonParsingError::toMatchKeyBindingToPayloadCnfError)
                .bind()
        }

        // match the public keys to find the correct key binding
        return@coroutineBinding confirmation?.let { cnf ->
            keyBindingJwkPairs.firstOrNull { (_, jwk) ->
                cnf.jwk.x == jwk.x && cnf.jwk.y == jwk.y
            }?.first
        } ?: Err(
            MatchKeyBindingToPayloadCnfError.Unexpected(
                IllegalStateException(
                    "No matching key binding available."
                )
            )
        ).bind<KeyBinding>()
    }

    private suspend fun KeyBinding.toJwk(): Jwk? {
        // KeyFactory.getInstance("ML-DSA", ...) parses the standard X.509/SubjectPublicKeyInfo
        // encoding — same encoding for both the software-stored raw bytes and
        // PublicKey#getEncoded() from an AndroidKeyStore-backed key, so both branches can share
        // one path (unlike the old EC code, ML-DSA public keys don't need an explicit curve
        // parameter passed alongside them).
        val publicKeyBytes: ByteArray = when (bindingType) {
            KeyBindingType.SOFTWARE -> publicKey
            KeyBindingType.HARDWARE -> getHardwareKeyPair(identifier, ANDROID_KEY_STORE).get()?.public?.encoded
        } ?: return null
        return mlDsaPublicKeyToJwk(rawPublicKey = publicKeyBytes, kid = null, certificateChainBase64 = null)
    }
}
