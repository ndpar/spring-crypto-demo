package com.ndpar.demo.crypto;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import javax.annotation.Resource;
import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Map;

import static org.junit.Assert.assertEquals;

@RunWith(SpringRunner.class)
@SpringBootTest
public class KeyStoreConfigTests {

    @Resource
    private Map<String, PrivateKey> privateKeys;

    @Resource
    private Map<String, PublicKey> publicKeys;

    @Resource
    private Map<String, Certificate> certificates;

    @Resource
    private Map<String, SecretKey> secretKeys;

    @Test
    public void contextLoads() {
        assertEquals(3, privateKeys.size());
        assertEquals(3, publicKeys.size());
        assertEquals(3, certificates.size());
        assertEquals(2, secretKeys.size());
    }
}
