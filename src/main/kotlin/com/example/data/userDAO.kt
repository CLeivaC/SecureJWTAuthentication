package com.example.data

import org.jetbrains.exposed.dao.id.IntIdTable
import org.jetbrains.exposed.sql.select
import org.jetbrains.exposed.sql.transactions.transaction

object Users: IntIdTable(){
    val email = varchar("email",100).uniqueIndex()
    val hashedPassword = varchar("hashed_password",400)
    val salt = varchar("salt",400)
    val token = varchar("token",400).nullable()
    val email_verified = bool("email_verified").default(false)
}
