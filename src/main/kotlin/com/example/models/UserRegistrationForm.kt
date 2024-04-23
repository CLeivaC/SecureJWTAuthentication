package com.example.models

import kotlinx.serialization.Serializable

@Serializable
data class UserRegistrationForm(
    val email: String,
    val password: String
)