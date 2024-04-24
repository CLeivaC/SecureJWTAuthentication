package com.example.repository

import com.example.data.UserSessionDAO
import com.example.models.UserSession

object UserSessionRepository {
    fun createSession(userId: Int, token: String): Int {
        return UserSessionDAO.insertSession(userId, token)
    }

    fun getAllSessions(): List<UserSession> {
        return UserSessionDAO.getAllSessions()
    }

    fun getSessionById(id: Int): UserSession? {
        return UserSessionDAO.getSessionById(id)
    }

    fun updateSession(id: Int, userId: Int, token: String): Boolean {
        return UserSessionDAO.updateSession(id, userId, token)
    }

    fun deleteSession(id: Int, userId: Int): Boolean {
        return UserSessionDAO.deleteSession(id, userId)
    }
}