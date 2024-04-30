package com.example.models

import kotlinx.serialization.Serializable
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneOffset


@Serializable
data class Challenger(
    val id: Int,
    val token: String,
    val userId: Int,
    val createdAt: Long,
    val expiresAt: Long, // Nueva columna para la fecha de expiración del token
    val verified: Boolean
) {
    companion object {
        fun fromLocalDateTime(localDateTime: LocalDateTime): Long {
            return localDateTime.toEpochSecond(ZoneOffset.UTC)
        }

        fun toLocalDateTime(epochSecond: Long): LocalDateTime {
            return LocalDateTime.ofInstant(Instant.ofEpochSecond(epochSecond), ZoneOffset.UTC)
        }
    }
}