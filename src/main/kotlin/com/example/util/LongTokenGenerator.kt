package com.example.util

import io.ktor.http.*
import java.security.SecureRandom

object LongTokenGenerator {
    private const val CHAR_LOWER = "abcdefghijklmnopqrstuvwxyz"
    private val CHAR_UPPER = CHAR_LOWER.toUpperCase()
    private const val NUMBER = "0123456789"
    private const val OTHER_CHAR = "!#*()_+-="

    private val SECURE_RANDOM = SecureRandom()

    private val ALL_CHARACTERS = CHAR_LOWER + CHAR_UPPER + NUMBER + OTHER_CHAR

    fun generate(length: Int): String {
        val sb = StringBuilder(length)
        for (i in 0 until length) {
            val randomIndex = SECURE_RANDOM.nextInt(ALL_CHARACTERS.length)
            sb.append(ALL_CHARACTERS[randomIndex])
        }
        return sb.toString()
    }
}