package ch.admin.foitt.openid4vc.domain.model.jwk

import com.github.michaelbull.result.coroutines.runSuspendCatching
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.Base64URL
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * https://datatracker.ietf.org/doc/html/rfc7517
 */
@Serializable
data class Jwk(
    @SerialName("x")
    val x: String? = null,
    @SerialName("y")
    val y: String? = null,
    @SerialName("crv")
    val crv: String? = null,
    @SerialName("kty")
    val kty: String,
    @SerialName("kid")
    val kid: String? = null,
    @SerialName("x5c")
    val x5c: List<String>? = null,
    @SerialName("use")
    val use: String? = null,
    @SerialName("alg")
    val alg: String? = null,
    @SerialName("pub")
    val pubKey: String? = null,
) {
    companion object {
        fun fromEcKey(
            ecKeyString: String,
            certificateChainBase64: List<String>?,
        ) = runSuspendCatching {
            ECKey.parse(ecKeyString).toEcJwk(certificateChainBase64)
        }
        fun fromJwkString(
            jwkString: String,
            certificateChainBase64: List<String>?,
        ) = runSuspendCatching {
            Json.decodeFromString<Jwk>(jwkString).copy(x5c = certificateChainBase64)
        }
    }
}

fun ECKey.toEcJwk(certificateChainBase64: List<String>?): Jwk = Jwk(
    x = x.toString(),
    y = y.toString(),
    crv = curve.name,
    kid = keyID,
    kty = keyType.value,
    x5c = certificateChainBase64,
)

fun mlDsaPublicKeyToJwk(
    rawPublicKey: ByteArray,
    kid: String?,
    certificateChainBase64: List<String>?,
    alg: String = "ML-DSA-44",
): Jwk = Jwk(
    kty = "AKP",
    kid = kid,
    x5c = certificateChainBase64,
    alg = alg,
    pubKey = Base64URL.encode(rawPublicKey).toString(),
)

fun Jwk.hasSameCurveAs(otherJwk: Jwk): Boolean =
    kty == otherJwk.kty &&
        crv == otherJwk.crv &&
        x == otherJwk.x &&
        y == otherJwk.y
