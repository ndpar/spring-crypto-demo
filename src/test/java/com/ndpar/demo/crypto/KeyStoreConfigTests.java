package com.ndpar.demo.crypto;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Map;

import static org.junit.Assert.assertEquals;

@RunWith(SpringRunner.class)
@SpringBootTest
public class KeyStoreConfigTests {

    @Autowired
    private Map<String, PrivateKey> privateKeys;

    @Autowired
    private Map<String, PublicKey> publicKeys;

    @Autowired
    private Map<String, Certificate> certificates;

    @Autowired
    private Map<String, SecretKey> secretKeys;

    @Test
    public void contextLoads() {
        assertEquals(3, privateKeys.size());
        assertEquals(3, publicKeys.size());
        assertEquals(3, certificates.size());
        assertEquals(2, secretKeys.size());
    }
}
