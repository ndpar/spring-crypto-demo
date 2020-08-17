package com.ndpar.demo.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.junit4.SpringRunner
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.*
import javax.annotation.Resource

@SpringBootTest
@RunWith(SpringRunner::class)
class CryptoTest {

    @Resource
    private lateinit var rootKey: PrivateKey

    @Resource
    private lateinit var rootCert: X509Certificate

    @Test
    fun `generate key pair and sign cert`() {
        val dn = "CN=Intermediate CA"

        val keyPair = generateKeyPair()
        val cert = signKey(keyPair.public, rootKey, rootCert, dn)

        assertTrue(157 < cert.serialNumber.bitLength())
        assertEquals(SIGNATURE_ALGORITHM, cert.sigAlgName)
        assertTrue(cert.issuerDN.name.contains("Root CA"))
        cert.checkValidity(Date() + 3600.days)
        assertEquals(dn, cert.subjectDN.name)
        assertEquals(keyPair.public, cert.publicKey)
        assertEquals(2, cert.criticalExtensionOIDs.size)
        assertEquals(2, cert.nonCriticalExtensionOIDs.size)
    }
}