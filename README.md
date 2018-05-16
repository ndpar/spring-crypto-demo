# Keystore Demo

Starting with JDK 9, PKCS #12 is a [default format](https://blogs.oracle.com/jtc/jdk9-keytool-transitions-default-keystore-to-pkcs12) of Java key store.

An excerpt from [RFC7292](https://tools.ietf.org/html/rfc7292) (PKCS #12):

> This standard describes a transfer syntax for personal identity
> information, including private keys, certificates, miscellaneous
> secrets, and extensions. Machines, applications, browsers, Internet
> kiosks, and so on, that support this standard will allow a user to
> import, export, and exercise a single set of personal identity
> information.

PKCS #12 supports the following data structures:

- KeyBag ::= PrivateKeyInfo
- PKCS8ShroudedKeyBag ::= EncryptedPrivateKeyInfo
- CertBag
- CRLBag
- SecretBag
- SafeContents

## Building Keystore

Package an existing private key

    openssl pkcs12 -export -in pkcs8.pem -out keystore.p12 -name private_key -nocerts -passout pass:changeit

Generate and package an EC key pair

    openssl ecparam -genkey -name secp256k1 -param_enc named_curve -out private.pem
    openssl req -new -config openssl-server.cnf -key private.pem -sha256 -out cert.csr -nodes
    openssl ca -config openssl-ca.cnf -policy signing_policy -extensions signing_req -out cert.crt -passin file:pass.txt -infiles cert.csr
    openssl pkcs12 -export -in cert.crt -inkey private.pem -out ec-keystore.p12 -name ec_key_pair -CAfile cacert.pem -caname root -chain -passout pass:changeit

Generate and package an RSA key pair

    openssl genrsa -out private.pem 2048
    openssl req -new -config openssl-server.cnf -key private.pem -sha256 -out cert.csr -nodes
    openssl ca -config openssl-ca.cnf -policy signing_policy -extensions signing_req -out cert.crt -passin file:pass.txt -infiles cert.csr
    openssl pkcs12 -export -in cert.crt -inkey private.pem -out rsa-keystore.p12 -name rsa_key_pair -CAfile cacert.pem -caname root -chain -passout pass:changeit

Generate and package an AES key

    keytool -genseckey -alias aes_key -keyalg AES -keysize 256 -storetype PKCS12 -keystore aes-keystore.p12 -storepass changeit

Merge three key pair keystores into the one with the private key. Unfortunately you cannot merge multiple private key keystores. If you want to do it, you need to add a (self-signed) certificate to the private key.

    keytool -importkeystore -srckeystore rsa-keystore.p12 -srcstoretype PKCS12 -srcstorepass changeit -destkeystore keystore.p12 -deststoretype PKCS12 -deststorepass changeit
    keytool -importkeystore -srckeystore ec-keystore.p12  -srcstoretype PKCS12 -srcstorepass changeit -destkeystore keystore.p12 -deststoretype PKCS12 -deststorepass changeit
    keytool -importkeystore -srckeystore aes-keystore.p12 -srcstoretype PKCS12 -srcstorepass changeit -destkeystore keystore.p12 -deststoretype PKCS12 -deststorepass changeit

Import a secret into the keystore

    keytool -importpass -alias secret -keystore keystore.p12 -storepass changeit -keypass changeit

Import a certificate into the keystore

    keytool -importcert -file ndpar.cer -keystore keystore.p12 -alias trusted_cert -storepass changeit


## Inspecting Keystore

base64-encode the keystore

    base64 -i keystore.p12

Copy/paste the output to `KEYSTORE` [environment variable](src/main/resources/application.yml).

Use [ASN.1 Decoder](http://lapo.it/asn1js/) to inspect the keystore.


## Using Keystore

[Here](src/main/java/com/ndpar/demo/crypto/KeyStoreConfig.java) is how you read the keystore,
and [here](src/test/java/com/ndpar/demo/crypto/KeyStoreConfigTests.java) is how you inject the crypto artifacts.


## Links

- Why [PKCS #12 is better](https://neilmadden.wordpress.com/2017/11/17/java-keystores-the-gory-details/) than JKS
- Commonly used [cryptographic commands](https://blog.ndpar.com/2017/04/24/cryptography-tools/)

