package com.example.routes

import com.example.data.ChallengerDAO
import com.example.data.Users
import com.example.models.UserRegistrationForm
import com.example.repository.UserSessionRepository
import com.example.util.LongTokenGenerator
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.jetbrains.exposed.sql.and
import org.jetbrains.exposed.sql.insertAndGetId
import org.jetbrains.exposed.sql.select
import org.jetbrains.exposed.sql.transactions.transaction
import org.jetbrains.exposed.sql.update
import java.security.MessageDigest
import java.time.Duration.*
import kotlin.random.Random
import java.util.Properties
import java.util.concurrent.TimeUnit
import javax.mail.*
import javax.mail.internet.InternetAddress
import javax.mail.internet.MimeMessage
import java.time.Duration
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.temporal.ChronoUnit


fun Route.authRoutes() {
    registerRoute()
    verifyEmailRoute()
    loginRoute()
    shortTokenRoute()
    protectedRoute()
    resendVerificationRoute()
    logoutRoute()

}

private fun Route.registerRoute(){
    post("/auth/register") {
        try {
            val registration = call.receive<UserRegistrationForm>()

            // Desestructura los campos del objeto de usuario
            val (email, password) = registration

            // Genera el salt y el token
            val salt = generateSalt()


            // Genera el hash de la contraseña
            val hashedPassword = hashPassword(email, password, salt)

            // Verificar si el usuario ya existe
            if (transaction { Users.select { Users.email eq email }.count() > 0 }) {
                call.respondText("User with this email already exists", status = HttpStatusCode.BadRequest)
            } else {
                // Registra el nuevo usuario en la base de datos
                val userId: Int = transaction {
                    Users.insertAndGetId {
                        // No necesitas establecer el ID, es autoincremental
                        it[Users.email] = email
                        it[Users.hashedPassword] = hashedPassword
                        it[Users.salt] = salt
                    // Asignar el token generado
                    }.value
                }

                // Guarda el token en la tabla challengers con la fecha de creación
                ChallengerDAO.saveToken(userId, LocalDateTime.now(),email)

                // Envía el correo de verificación


                call.respondText("User registered successfully")
            }
        } catch (e: SerializationException) {
            call.respond(HttpStatusCode.BadRequest, "Invalid JSON format")
        }

    }
}


private fun Route.verifyEmailRoute() {
    // Ruta para manejar la verificación de correo electrónico
    get("/auth/verify-email") {
        val email = call.parameters["email"] ?: run {
            call.respondText("Email parameter missing", status = HttpStatusCode.BadRequest)
            return@get
        }

        val token = call.parameters["token"] ?: run {
            call.respondText("Token parameter missing", status = HttpStatusCode.BadRequest)
            return@get
        }

        // Buscar el usuario por su correo electrónico para obtener el userID
        val user = transaction {
            Users.select { Users.email eq email }.singleOrNull()
        }

        if (user == null) {
            call.respondText("User not found", status = HttpStatusCode.BadRequest)
            return@get
        }

        val userId = user[Users.id]

        // Verificar si el token es válido para el usuario
        val tokenRow = ChallengerDAO.findTokenByUserIdAndToken(userId.value, token)
        if (tokenRow == null) {
            call.respondText("Invalid or expired token", status = HttpStatusCode.BadRequest)
            return@get
        }

        // Actualizar el estado de emailVerified en la base de datos
        transaction {
            Users.update({ Users.email eq email }) {
                it[email_verified] = true
            }
        }

        // Eliminar los tokens expirados
        ChallengerDAO.deleteExpiredTokens()

        call.respondText("Email verification successful")
    }
}


private fun Route.loginRoute(){
    post("/auth/login") {
        val parameters = call.receiveParameters()
        val email =
            parameters["email"] ?: return@post call.respondText("Missing email", status = HttpStatusCode.BadRequest)
        val password = parameters["password"] ?: return@post call.respondText(
            "Missing password",
            status = HttpStatusCode.BadRequest
        )

        val userRow = transaction { Users.select { Users.email eq email }.singleOrNull() }

        if (userRow == null) {
            call.respondText("User not found", status = HttpStatusCode.BadRequest)
        } else {
            val hashedPassword = hashPassword(email, password, userRow[Users.salt])

            if (hashedPassword == userRow[Users.hashedPassword]) {
                // Verificar si el correo electrónico está verificado
                val emailVerified = userRow[Users.email_verified]
                /*if (!emailVerified) {
                    call.respondText("Email not verified. Please verify your email before logging in.", status = HttpStatusCode.BadRequest)
                    return@post
                }*/

                // Generar token largo
                val tokenLong = LongTokenGenerator.generate(32) // Longitud del token (32 caracteres)

                // Crear sesión y obtener su ID
                val sessionId = UserSessionRepository.createSession(userRow[Users.id].value, tokenLong)

                // Informar al usuario que ha iniciado sesión exitosamente
                call.respondText("Login successful, session ID: $sessionId,$tokenLong")
            } else {
                call.respondText("Incorrect email or password", status = HttpStatusCode.BadRequest)
            }
        }
    }
}


private fun Route.shortTokenRoute(){
    post("/auth/token") {
        val parameters = call.receiveParameters()
        val sessionId = parameters["sessionId"]?.toIntOrNull()
        val tokenLong = parameters["tokenLong"]

        if (sessionId == null || tokenLong == null) {
            call.respond(HttpStatusCode.BadRequest, "Missing session ID or long token")
            return@post
        }

        // Verificar si la sesión existe en la base de datos
        val session = UserSessionRepository.getSessionById(sessionId)
        if (session == null || session.token != tokenLong) {
            call.respond(HttpStatusCode.BadRequest, "Invalid session ID or long token")
            return@post
        }
        // Obtener el email del usuario para generar el token corto (JWT)
        val userRow = transaction { Users.select { Users.id eq session.userId }.singleOrNull() }
        if (userRow == null) {
            call.respond(HttpStatusCode.BadRequest, "User not found")
            return@post
        }
        val userEmail = userRow[Users.email]

        // Crear el token JWT
        val token = JwtUtils.generateAccessToken(userEmail)

        // Responder con el token generado
        val jsonResponse = buildJsonObject {
            put("token", token)
        }
        val jsonString = Json.encodeToString(JsonObject.serializer(), jsonResponse)
        call.respondText(jsonString, ContentType.Application.Json, HttpStatusCode.OK)
    }
}

private fun Route.logoutRoute(){
    post("/auth/logout") {
        val parameters = call.receiveParameters()
        val sessionId = parameters["sessionId"]?.toIntOrNull()
        val tokenLong = parameters["tokenLong"]

        if (sessionId == null || tokenLong == null) {
            call.respondText("Missing session ID or long token", status = HttpStatusCode.BadRequest)
            return@post
        }

        // Verificar si la sesión existe en la base de datos
        val session = UserSessionRepository.getSessionById(sessionId)
        if (session == null || session.token != tokenLong) {
            call.respondText("Invalid session ID or long token", status = HttpStatusCode.BadRequest)
            return@post
        }

        // Obtener el id del usuario asociado a la sesión
        val userId = session.userId

        // Eliminar la sesión de la base de datos
        val deleted = UserSessionRepository.deleteSession(sessionId, userId)

        if (deleted) {
            call.respondText("Logout successful")
        } else {
            call.respondText("Failed to logout", status = HttpStatusCode.InternalServerError)
        }
    }
}

private fun Route.resendVerificationRoute() {
    authenticate("jwt") { // Agregar middleware de autenticación JWT
        post("/auth/resend-verification") {
            val principal = call.principal<JWTPrincipal>()
            val email = principal?.payload?.getClaim("email")?.asString()
            if (email != null) {
                val user = transaction { Users.select { Users.email eq email }.singleOrNull() }
                if (user != null) {
                    val emailVerified = user[Users.email_verified]
                    if (!emailVerified) {
                        // El usuario existe pero su correo aún no está verificado
                        val userId = user[Users.id]

                        // Verificar si ha pasado al menos 5 minutos desde el último correo de verificación enviado
                        val lastVerificationEmailSentAt = ChallengerDAO.getLastVerificationEmailSentAt(userId.value)
                        val currentTime = LocalDateTime.now()
                        val maxTimeForNewVerificationEmail = lastVerificationEmailSentAt?.let {
                            Instant.ofEpochMilli(it).plus(Duration.ofMinutes(5))
                        }
                        if (lastVerificationEmailSentAt == null || maxTimeForNewVerificationEmail?.let { it <= currentTime.atZone(
                                ZoneId.systemDefault()).toInstant() } == true) {
                            transaction {
                                ChallengerDAO.saveToken(userId.value, currentTime, email)
                            }
                            call.respondText("Se ha enviado un nuevo correo de verificación.")
                        } else {
                            call.respondText("Debes esperar al menos 5 minutos antes de solicitar otro correo de verificación.", status = HttpStatusCode.BadRequest)
                        }
                    } else {
                        call.respondText("El correo ya está verificado.")
                    }
                } else {
                    call.respondText("Usuario no encontrado.", status = HttpStatusCode.NotFound)
                }
            } else {
                call.respondText("Correo electrónico no encontrado en el token de autenticación.", status = HttpStatusCode.BadRequest)
            }
        }
    }
}



private fun Route.protectedRoute(){
    authenticate("jwt") {
        get("/auth/protected") {
            val principal = call.principal<JWTPrincipal>()
            val username = principal!!.payload.getClaim("email").asString()
            val expiresAt = principal.expiresAt?.time?.minus(System.currentTimeMillis())
            call.respondText("Hello, $username! Token is expired at $expiresAt ms.")
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



