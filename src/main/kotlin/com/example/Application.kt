package com.example

import com.auth0.jwt.JWT
import com.auth0.jwt.JWTVerifier
import com.auth0.jwt.algorithms.Algorithm
import com.example.data.Users
import com.example.models.User
import com.example.plugins.configureRouting
import com.example.plugins.configureSecurity
import com.example.plugins.configureSerialization
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.selectAll
import org.jetbrains.exposed.sql.transactions.transaction
import java.util.*

fun main() {
    val server = embeddedServer(Netty, port = 8080) {
        module()
    }
    server.start(wait = true)
}

fun Application.module() {
    install(Authentication) {
        jwt("jwt") {
            val secret = "my_secret_key" // Clave secreta para firmar el token (cámbiala por una clave segura en un entorno real)
            val issuer = "Ktor Server" // Emisor del token (puedes cambiarlo según tu aplicación)

            val algorithm = Algorithm.HMAC256(secret)
            val verifier: JWTVerifier = JWT
                .require(algorithm)
                .withIssuer(issuer)
                .build()

            verifier(verifier)
            realm = "Ktor Server"
            validate { credential ->

                val email = credential.subject
                if (email != null) {
                    val user = isValidUser(email)
                    user?.let { UserIdPrincipal(it.email) }
                } else {
                    null
                }
            }
        }
    }

    databaseConexion()
    configureSecurity()
    configureSerialization()
    configureRouting()
}

fun isValidUser(email: String): User? {
    val userRow = transaction { Users.selectAll().where { Users.email eq email }.singleOrNull() }
    return userRow?.let {
        User(
            it[Users.email],
            it[Users.hashedPassword],
            it[Users.salt],
            it[Users.token]
        )
    }
}

private fun databaseConexion() {
    Database.connect(
        "jdbc:mysql://localhost:3306/prueba_register_login",
        driver = "com.mysql.cj.jdbc.Driver",
        user = "root",
        password = "admin"
    )
}
