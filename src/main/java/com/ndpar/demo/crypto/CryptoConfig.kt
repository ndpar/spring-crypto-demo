package com.ndpar.demo.crypto

import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
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
    fun rootKey(): PrivateKey {
        val parser = PEMParser(StringReader(rootKey))
        val pem = parser.readObject() as PEMKeyPair
        return JcaPEMKeyConverter().getKeyPair(pem).private
    }

    @Bean
    fun rootCert(): X509Certificate {
        val parser = PEMParser(StringReader(rootCert))
        val pem = parser.readObject() as X509CertificateHolder
        return JcaX509CertificateConverter().getCertificate(pem)
    }
}
