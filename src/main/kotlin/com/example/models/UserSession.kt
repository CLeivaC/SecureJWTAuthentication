package com.example.models

import kotlinx.serialization.Serializable

@Serializable
data class UserSession(
        val id: Int,
        val userId:Int,
        val token:String
        )