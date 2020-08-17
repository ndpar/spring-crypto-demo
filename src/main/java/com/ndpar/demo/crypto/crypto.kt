package com.ndpar.demo.crypto

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import java.io.Reader
import java.io.StringWriter
import java.io.Writer
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.*

const val KEY_ALGORITHM = "EC"
const val SIGNATURE_ALGORITHM = "SHA256withECDSA"

fun generateKeyPair(curveName: String = "secp256r1"): KeyPair =
    with(KeyPairGenerator.getInstance(KEY_ALGORITHM)) {
        initialize(ECGenParameterSpec(curveName))
        generateKeyPair()
    }

fun signKey(
    publicKey: PublicKey,
    caKey: PrivateKey,
    caCert: X509Certificate,
    dn: String,
    days: Int = 3650,
    extensions: List<Extension> = caExtensions(publicKey, caCert)
): X509Certificate {

    val signer = JcaContentSignerBuilder(SIGNATURE_ALGORITHM).build(caKey)
    val csrBuilder = JcaPKCS10CertificationRequestBuilder(X500Name(dn), publicKey)
    val csr: PKCS10CertificationRequest = csrBuilder.build(signer)

    val serialNumber = BigInteger(160, SecureRandom())
    val startDate = Date()
    val endDate = startDate + days.days

    val certBuilder = X509v3CertificateBuilder(
        X500Name(caCert.issuerDN.name),
        serialNumber,
        startDate,
        endDate,
        csr.subject,
        csr.subjectPublicKeyInfo
    )
    extensions.forEach { certBuilder.addExtension(it) }

    val certHolder = certBuilder.build(signer)
    return JcaX509CertificateConverter().getCertificate(certHolder)
}

fun dhExtensions(publicKey: PublicKey, rootCert: X509Certificate): List<Extension> {
    val issuedCertExtUtils = JcaX509ExtensionUtils()
    return listOf(
        ext(Extension.basicConstraints, true, BasicConstraints(false)),
        ext(Extension.subjectKeyIdentifier, false, issuedCertExtUtils.createSubjectKeyIdentifier(publicKey)),
        ext(Extension.authorityKeyIdentifier, false, issuedCertExtUtils.createAuthorityKeyIdentifier(rootCert)),
        ext(Extension.keyUsage, true, KeyUsage(KeyUsage.keyAgreement))
    )
}

fun caExtensions(publicKey: PublicKey, rootCert: X509Certificate): List<Extension> {
    val issuedCertExtUtils = JcaX509ExtensionUtils()
    return listOf(
        ext(Extension.subjectKeyIdentifier, false, issuedCertExtUtils.createSubjectKeyIdentifier(publicKey)),
        ext(Extension.authorityKeyIdentifier, false, issuedCertExtUtils.createAuthorityKeyIdentifier(rootCert)),
        ext(Extension.basicConstraints, true, BasicConstraints(true)),
        // TODO ext(Extension.keyUsage, true, KeyUsage(KeyUsage.cRLSign)),
        ext(Extension.keyUsage, true, KeyUsage(KeyUsage.keyCertSign))
    )
}

private fun ext(oid: ASN1ObjectIdentifier, isCritical: Boolean, value: ASN1Encodable): Extension =
    Extension(oid, isCritical, DEROctetString(value))

fun Reader.readPrivateKey(): PrivateKey {
    val parser = PEMParser(this)
    val pem = parser.readObject() as PEMKeyPair
    return JcaPEMKeyConverter().getKeyPair(pem).private
}

fun Reader.readCert(): X509Certificate {
    val parser = PEMParser(this)
    val pem = parser.readObject() as X509CertificateHolder
    return JcaX509CertificateConverter().getCertificate(pem)
}

fun Any.toPem(writer: Writer = StringWriter()): Writer = writer.also { w ->
    JcaPEMWriter(w).use {
        it.writeObject(this)
        it.flush()
    }
}
