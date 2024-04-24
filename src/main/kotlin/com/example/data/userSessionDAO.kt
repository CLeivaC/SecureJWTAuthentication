package com.example.data

import com.example.models.UserSession
import org.jetbrains.exposed.sql.*
import org.jetbrains.exposed.sql.SqlExpressionBuilder.eq
import org.jetbrains.exposed.sql.transactions.transaction

object UserSessions: Table(){
    val id = integer("id").autoIncrement()
    val  userId = integer("user_id").references(Users.id)
    val token = text("token")

    override val primaryKey = PrimaryKey(id)
}

object UserSessionDAO {
    val table = UserSessions

    fun insertSession(userId: Int, token: String): Int {
        return transaction {
            table.insert {
                it[table.userId] = userId
                it[table.token] = token
            } get table.id
        }
    }

    fun getAllSessions(): List<UserSession> {
        return transaction {
            table.selectAll().map { toUserSession(it) }
        }
    }

    fun getSessionById(id: Int): UserSession? {
        return transaction {
            table.select { table.id eq id }
                .mapNotNull { toUserSession(it) }
                .singleOrNull()
        }
    }

    fun updateSession(id: Int, userId: Int, token: String): Boolean {
        return transaction {
            table.update({ table.id eq id }) {
                it[table.userId] = userId
                it[table.token] = token
            } > 0
        }
    }

    fun deleteSession(id: Int, userId: Int): Boolean {
        return transaction {
            val affectedRows = table.deleteWhere {
                (table.id eq id) and (table.userId eq userId)
            }
            affectedRows > 0
        }
    }

    private fun toUserSession(row: ResultRow): UserSession {
        return UserSession(
            id = row[table.id],
            userId = row[table.userId],
            token = row[table.token]
        )
    }
}