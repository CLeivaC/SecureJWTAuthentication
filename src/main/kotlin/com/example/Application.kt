package com.example
import com.auth0.jwt.exceptions.JWTVerificationException
import com.example.data.Users
import com.example.models.User
import com.example.plugins.configureRouting
import com.example.plugins.configureSecurity
import com.example.plugins.configureSerialization
import com.typesafe.config.ConfigFactory
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.config.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*

import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.selectAll
import org.jetbrains.exposed.sql.transactions.transaction

fun main() {
    val server = embeddedServer(Netty, port = 8080) {
        module()
    }
    server.start(wait = true)
}

fun Application.module() {
    install(Authentication) {
        jwt("jwt") {
            verifier(JwtUtils.buildVerifier())
            realm = JwtInfo.myRealm
            validate { credential ->
                try {
                    // Verificar reclamación 'iss'
                    val issuer = credential.payload.issuer
                    if (issuer != JwtInfo.issuer) {
                        return@validate null // Emisor no válido
                    }

                    // Obtener y validar reclamación 'email'
                    val email = credential.payload.getClaim("email").asString()
                    isValidUser(email)?.let { JWTPrincipal(credential.payload) }
                } catch (e: JWTVerificationException) {
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
    return transaction { Users.selectAll().where { Users.email eq email }.singleOrNull() }?.let {
        User(
            it[Users.email],
            it[Users.hashedPassword],
            it[Users.salt],
            it[Users.token]
        )
    }
}

private fun databaseConexion() {
    val dbUrl = "jdbc:mysql://localhost:3306/prueba_register_login"
    val driver = "com.mysql.cj.jdbc.Driver"
    val user = "root"
    val password = "admin"

    Database.connect(dbUrl, driver, user, password)
}

object JwtInfo {
    private val config = HoconApplicationConfig(ConfigFactory.load("application.conf"))

    val issuer get() = config.property("jwt.issuer").getString()
    val audience get() = config.property("jwt.audience").getString()
    val myRealm get() = config.property("jwt.realm").getString()
}

