package com.example.models

import kotlinx.serialization.Serializable

@Serializable
data class User(
    val email: String,
    val hashed_password: String,
    val salt: String,
    val token: String?
)

