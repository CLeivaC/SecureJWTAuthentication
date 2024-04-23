package com.example.routes

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.example.data.Users
import com.example.models.User
import com.example.models.UserRegistrationForm
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.security.Keys
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import org.jetbrains.exposed.sql.insert
import org.jetbrains.exposed.sql.select
import org.jetbrains.exposed.sql.transactions.transaction
import org.jetbrains.exposed.sql.update
import java.security.MessageDigest
import java.util.*
import kotlin.random.Random

fun Route.register() {
    post("/auth/register") {
        try {
            val registration = call.receive<UserRegistrationForm>()

            // Desestructura los campos del objeto de usuario
            val (email, password) = registration

            // Genera el salt y el token
            val salt = generateSalt()

            // Genera el hash de la contraseña
            val hashedPassword = hashPassword(email, password, salt)

            val user = User(email, hashedPassword, salt, null)
            val token = generateToken(user)

            // Verificar si el usuario ya existe
            if (transaction { Users.select { Users.email eq email }.count() > 0 }) {
                call.respondText("User with this email already exists", status = HttpStatusCode.BadRequest)
            } else {
                // Registra el nuevo usuario en la base de datos
                transaction {
                    Users.insert {
                        // No necesitas establecer el ID, es autoincremental
                        it[Users.email] = email
                        it[Users.hashedPassword] = hashedPassword
                        it[Users.salt] = salt
                        it[Users.token] = token // No estás usando el token aún
                    }
                }

                call.respondText("User registered successfully")
            }
        } catch (e: SerializationException) {
            call.respond(HttpStatusCode.BadRequest, "Invalid JSON format")
        }

    }
    post("/auth/login") {
        val parameters = call.receiveParameters()
        val email = parameters["email"] ?: return@post call.respondText("Missing email", status = HttpStatusCode.BadRequest)
        val password = parameters["hashed_password"] ?: return@post call.respondText("Missing password", status = HttpStatusCode.BadRequest)

        val userRow = transaction { Users.select { Users.email eq email }.singleOrNull() }

        if (userRow == null) {
            call.respondText("User not found", status = HttpStatusCode.BadRequest)
        } else {
            val hashedPassword = hashPassword(email, password, userRow[Users.salt])

            if (hashedPassword == userRow[Users.hashedPassword]) {
                // El usuario ha sido autenticado correctamente, ahora generamos un nuevo token
                val user = User(userRow[Users.email], userRow[Users.hashedPassword], userRow[Users.salt], userRow[Users.token])
                val token = generateToken(user)

                // Actualizamos el token en la base de datos
                transaction {
                    Users.update({ Users.email eq email }) {
                        it[Users.token] = token
                    }
                }
                call.respondText("Login successful, token: $token")
            } else {
                call.respondText("Incorrect email or password", status = HttpStatusCode.BadRequest)
            }
        }
    }
    authenticate("jwt") {
        get("/auth/protected") {
            call.respondText("Hello, ${call.principal<UserIdPrincipal>()?.name}")
        }
    }
}
private fun generateSalt(): String {
    val salt = ByteArray(16)
    Random.nextBytes(salt)
    return salt.joinToString("") { "%02x".format(it) }
}

fun hashPassword(email: String, password: String, salt: String): String {
    val md = MessageDigest.getInstance("SHA-512")
    md.update(salt.toByteArray())
    md.update(email.toByteArray())
    return md.digest(password.toByteArray()).joinToString("") { "%02x".format(it) }
}

fun generateToken(user: User): String {
    val secret = "my_secret_key" // Clave secreta para firmar el token
    val issuer = "Ktor Server" // Emisor del token 

    val algorithm = Algorithm.HMAC256(secret)
    val expirationTimeMillis = 24 * 60 * 60 * 1000 // Tiempo de expiración del token en milisegundos (aquí, 1 día)

    return JWT.create()
        .withSubject(user.email)
        .withExpiresAt(Date(System.currentTimeMillis() + expirationTimeMillis))
        .withIssuer(issuer)
        .sign(algorithm)
}