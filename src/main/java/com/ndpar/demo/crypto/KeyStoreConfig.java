package com.ndpar.demo.crypto;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@Configuration
public class KeyStoreConfig {

    @Value("${KEYSTORE}")
    private String keyStore;
    @Value("${KEYSTORE_PASSWORD}")
    private String storePassword;

    @Bean
    public KeyStore keyStore() throws Exception {
        KeyStore ks = KeyStore.getInstance("pkcs12");
        ks.load(new ByteArrayInputStream(keyStoreBytes()), storePassword());
        return ks;
    }

    @Bean
    public Map<String, PrivateKey> privateKeys() throws Exception {
        Map<String, PrivateKey> result = new HashMap<>();
        KeyStore keyStore = keyStore();
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (keyStore.isKeyEntry(alias)) {
                Key key = keyStore.getKey(alias, keyPassword());
                if (PrivateKey.class.isAssignableFrom(key.getClass())) {
                    result.put(alias, (PrivateKey) key);
                }
            }
        }
        return result;
    }

    @Bean
    public Map<String, PublicKey> publicKeys() throws Exception {
        return certificates().entrySet().stream()
                             .collect(Collectors.toMap(
                                     Map.Entry::getKey,
                                     e -> e.getValue().getPublicKey()));
    }

    @Bean
    public Map<String, Certificate> certificates() throws Exception {
        Map<String, Certificate> result = new HashMap<>();
        KeyStore keyStore = keyStore();
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            Certificate cert = keyStore.getCertificate(alias);
            if (cert != null) {
                result.put(alias, cert);
            }
        }
        return result;
    }

    @Bean
    public Map<String, SecretKey> secretKeys() throws Exception {
        Map<String, SecretKey> result = new HashMap<>();
        KeyStore keyStore = keyStore();
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (keyStore.isKeyEntry(alias)) {
                Key key = keyStore.getKey(alias, keyPassword());
                if (SecretKey.class.isAssignableFrom(key.getClass())) {
                    result.put(alias, (SecretKey) key);
                }
            }
        }
        return result;
    }

    private byte[] decode(String encodedString) {
        return Base64.getDecoder().decode(encodedString);
    }

    private byte[] keyStoreBytes() {
        return decode(keyStore);
    }

    private char[] storePassword() {
        return storePassword.toCharArray();
    }

    /**
     * Same as store password in PKCS #12.
     */
    private char[] keyPassword() {
        return storePassword();
    }
}
