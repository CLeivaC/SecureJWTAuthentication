package com.example.services

import java.util.Properties
import javax.mail.*
import javax.mail.internet.InternetAddress
import javax.mail.internet.MimeMessage

class EmailService {
    companion object {
        private const val username = "cristhian.leiva.cruz@gmail.com"
        private const val password = "lwvtkeghgnbojlwl"
        private const val subject = "Verificación de correo electrónico"

        fun sendVerificationEmail(email: String, token: String) {
            val session = configureSession()

            try {
                val message = MimeMessage(session)
                message.setFrom(InternetAddress(username))
                message.setRecipients(
                    Message.RecipientType.TO,
                    InternetAddress.parse(email)
                )
                message.subject = subject
                message.setText("Por favor, haz clic en el siguiente enlace para verificar tu dirección de correo electrónico: http://127.0.0.1:8080/auth/verify-email?email=$email&token=$token")

                Transport.send(message)

                println("Correo electrónico de verificación enviado exitosamente a $email")
            } catch (e: MessagingException) {
                // Manejar la excepción de manera adecuada, como registrarla o lanzar una excepción específica
                println("Error al enviar el correo electrónico de verificación a $email: ${e.message}")
            }
        }

        private fun configureSession(): Session {
            val props = Properties()
            props["mail.smtp.auth"] = "true"
            props["mail.smtp.starttls.enable"] = "true"
            props["mail.smtp.host"] = "smtp.gmail.com"
            props["mail.smtp.port"] = "587"

            return Session.getInstance(props,
                object : Authenticator() {
                    override fun getPasswordAuthentication(): PasswordAuthentication {
                        return PasswordAuthentication(username, password)
                    }
                })
        }
    }
}
