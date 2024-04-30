package com.example.data

import com.example.services.EmailService
import com.example.util.LongTokenGenerator
import org.jetbrains.exposed.sql.*
import org.jetbrains.exposed.sql.SqlExpressionBuilder.lessEq
import org.jetbrains.exposed.sql.transactions.transaction
import java.time.LocalDateTime
import java.time.ZoneOffset

object Challengers : Table("challengers") {
    val id = integer("id").autoIncrement()
    val token = varchar("token", 255)
    val userId = integer("user_id").references(Users.id)
    val createdAt = long("created_at")
    val expiresAt = long("expires_at") // Columna para la fecha de expiración

    override val primaryKey = PrimaryKey(id)

}

class ChallengerDAO {
    companion object {
        fun saveToken(userId: Int,createdAt: LocalDateTime,email:String) {
            val expirationTime = createdAt.plusMinutes(5) // Definir tiempo de expiración
            val expirationMillis = expirationTime.toInstant(ZoneOffset.UTC).toEpochMilli()
            val token = LongTokenGenerator.generate(32) // Generar el token aquí
            transaction {
                Challengers.insert {
                    it[Challengers.token] = token
                    it[Challengers.userId] = userId
                    it[Challengers.createdAt] = createdAt.toInstant(ZoneOffset.UTC).toEpochMilli()
                    it[expiresAt] = expirationMillis // Guardar tiempo de expiración
                }
            }
            EmailService.sendVerificationEmail(email,token)
        }

        fun findTokenByUserIdAndToken(userId: Int, token: String): ResultRow? {
            return transaction {
                val nowMillis = System.currentTimeMillis()
                Challengers.select {
                    (Challengers.userId eq userId) and
                            (Challengers.token eq token) and
                            (Challengers.expiresAt greaterEq nowMillis)
                }.singleOrNull()
            }
        }

        fun deleteExpiredTokens() {
            val now = LocalDateTime.now()
            val timeExpired = now.plusMinutes(5) // Calcula el tiempo límite para la expiración
            val timeExpiredMillis = timeExpired.toInstant(ZoneOffset.UTC).toEpochMilli()
            transaction {
                Challengers.deleteWhere { Challengers.expiresAt lessEq timeExpiredMillis }
            }
        }

        fun getLastVerificationEmailSentAt(userId: Int): Long? {
            return transaction {
                Challengers.slice(Challengers.createdAt)
                    .select { Challengers.userId eq userId }
                    .orderBy(Challengers.createdAt, SortOrder.DESC)
                    .limit(1)
                    .singleOrNull()?.getOrNull(Challengers.createdAt)
            }
        }


    }
}