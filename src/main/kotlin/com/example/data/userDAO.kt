package com.example.data

import org.jetbrains.exposed.dao.id.IntIdTable

object Users: IntIdTable(){
    val email = varchar("email",100).uniqueIndex()
    val hashedPassword = varchar("hashed_password",400)
    val salt = varchar("salt",400)
    val token = varchar("token",400).nullable()
}
