import com.auth0.jwt.JWT
import com.auth0.jwt.JWTVerifier
import com.auth0.jwt.algorithms.Algorithm
import com.example.JwtInfo
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.*

object JwtUtils {

    private val accessExpirationMs = 9600000L
    private val keyPair: KeyPair by lazy { generateJwtKeyPair() }

    fun generateAccessToken(email: String): String {
        return JWT.create()
            .withSubject(email)
            .withIssuer(JwtInfo.issuer) // Configurar el emisor
            .withAudience(JwtInfo.audience)
            .withClaim("email", email)
            .withIssuedAt(Date())
            .withExpiresAt(Date(System.currentTimeMillis() + accessExpirationMs))
            .sign(Algorithm.RSA256(null, keyPair.private as RSAPrivateKey))
    }

    fun buildVerifier(): JWTVerifier {
        val rsaPublicKey = keyPair.public as RSAPublicKey
        return JWT.require(Algorithm.RSA256(rsaPublicKey, null))
            .withIssuer(JwtInfo.issuer)
            .withAudience(JwtInfo.audience)
            .build()
    }

    private fun generateJwtKeyPair(): KeyPair {
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        return kpg.generateKeyPair()
    }
}
