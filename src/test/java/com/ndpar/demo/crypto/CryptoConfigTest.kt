package com.ndpar.demo.crypto

import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.junit4.SpringRunner
import java.security.PrivateKey
import java.security.cert.X509Certificate
import javax.annotation.Resource

@SpringBootTest
@RunWith(SpringRunner::class)
class CryptoConfigTest {

    @Resource
    private lateinit var rootKey: PrivateKey

    @Resource
    private lateinit var rootCert: X509Certificate

    @Test
    fun `read root key`() {
        assertEquals("ECDSA", rootKey.algorithm)
    }

    @Test
    fun `read root cert`() {
        assertEquals("X.509", rootCert.type)
        assertEquals(rootCert.subjectDN.name, rootCert.issuerDN.name)
    }
}