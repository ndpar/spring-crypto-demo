package com.ndpar.demo.crypto

import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import java.io.StringReader
import java.security.PrivateKey
import java.security.cert.X509Certificate

/**
 * For simplicity, reads PEM files from application.properties.
 * In production they would be read from the Vault.
 */
@Configuration
class CryptoConfig(
    @Value("\${com.ndpar.crypto.root.key}") private val rootKey: String,
    @Value("\${com.ndpar.crypto.root.cert}") private val rootCert: String
) {
    @Bean
    fun rootKey(): PrivateKey = StringReader(rootKey).readPrivateKey()

    @Bean
    fun rootCert(): X509Certificate = StringReader(rootCert).readCert()
}
