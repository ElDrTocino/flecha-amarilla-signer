package org.flechaamarilla.service;

import jakarta.enterprise.context.ApplicationScoped;
import org.apache.commons.io.IOUtils;

import javax.xml.crypto.dsig.*;
import javax.xml.transform.*;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;

import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;

@ApplicationScoped
public class SignerService {

    private static final String XSLT_PATH = "cadenaoriginal_3_3.xslt";
    private static final String CSD_KEY_PATH = "csd-pkcs8.key";
    private static final String CSD_KEY_PASS = "12345678a";
    private static final String CSD_CERT_PATH = "CSD_Pruebas_CFDI_SPR190613I52.cer";

    public String signXml(String xml) throws Exception {
        String cadenaOriginal = generarCadenaOriginal(xml);
        String sello = generarSelloDigital(cadenaOriginal);
        String certificado = cargarCertificadoBase64();
        String noCertificado = extraerNumeroCertificado();

        // Replace existing attributes or add them if they don't exist
        xml = replaceAttributeValue(xml, "Sello", sello);
        xml = replaceAttributeValue(xml, "Certificado", certificado);
        xml = replaceAttributeValue(xml, "NoCertificado", noCertificado);

        return xml;
    }

    private String replaceAttributeValue(String xml, String attribute, String value) {
        // If attribute exists, replace its value
        if (xml.matches("(?s).*" + attribute + "=\"[^\"]*\".*")) {
            return xml.replaceFirst(
                    "(" + attribute + "=\")[^\"]*\"",
                    "$1" + value + "\"");
        }
        // Otherwise, add it after the opening tag and before the first attribute
        else {
            return xml.replaceFirst(
                    "<Comprobante",
                    "<Comprobante " + attribute + "=\"" + value + "\"");
        }
    }

    private String generarCadenaOriginal(String xml) throws Exception {
        InputStream xsltStream = getClass().getClassLoader().getResourceAsStream(XSLT_PATH);
        if (xsltStream == null) {
            throw new FileNotFoundException("XSLT resource not found: " + XSLT_PATH);
        }

        TransformerFactory tf = TransformerFactory.newInstance();
        StreamSource xslt = new StreamSource(xsltStream);
        Transformer transformer = tf.newTransformer(xslt);

        StringWriter writer = new StringWriter();
        transformer.transform(new StreamSource(new StringReader(xml)), new StreamResult(writer));

        return writer.toString();
    }

    private String generarSelloDigital(String cadenaOriginal) throws Exception {
        PrivateKey privateKey = cargarLlavePrivada();
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(cadenaOriginal.getBytes(StandardCharsets.UTF_8));
        byte[] signed = signature.sign();
        return Base64.getEncoder().encodeToString(signed);
    }

private PrivateKey cargarLlavePrivada() throws Exception {
    InputStream keyStream = getClass().getClassLoader().getResourceAsStream(CSD_KEY_PATH);
    if (keyStream == null) {
        throw new FileNotFoundException("Key file not found: " + CSD_KEY_PATH);
    }

    byte[] keyBytes = IOUtils.toByteArray(keyStream);

    try {
        // Register Bouncy Castle provider if not already done
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        // Try to read as regular PKCS#8 key first
        try {
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(spec);
        } catch (Exception e) {
            // If that fails, try to decrypt the key
            PEMParser pemParser = new PEMParser(new StringReader(new String(keyBytes, StandardCharsets.UTF_8)));
            Object pemObject = pemParser.readObject();

            if (pemObject instanceof PKCS8EncryptedPrivateKeyInfo) {
                // Handle encrypted PKCS#8 key
                PKCS8EncryptedPrivateKeyInfo encryptedInfo = (PKCS8EncryptedPrivateKeyInfo) pemObject;
                JcePKCSPBEInputDecryptorProviderBuilder builder = new JcePKCSPBEInputDecryptorProviderBuilder();
                InputDecryptorProvider provider = builder.build(CSD_KEY_PASS.toCharArray());
                PrivateKeyInfo privateKeyInfo = encryptedInfo.decryptPrivateKeyInfo(provider);
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
                return converter.getPrivateKey(privateKeyInfo);
            } else if (pemObject instanceof PEMEncryptedKeyPair) {
                // Handle encrypted PEM key pair
                PEMEncryptedKeyPair encryptedKeyPair = (PEMEncryptedKeyPair) pemObject;
                PEMDecryptorProvider decryptorProvider = new JcePEMDecryptorProviderBuilder().build(CSD_KEY_PASS.toCharArray());
                PEMKeyPair keyPair = encryptedKeyPair.decryptKeyPair(decryptorProvider);
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
                return converter.getPrivateKey(keyPair.getPrivateKeyInfo());
            }

            throw new Exception("Unsupported key format");
        }
    } catch (Exception e) {
        throw new Exception("Unable to decode key: " + e.getMessage(), e);
    }
}


    private String cargarCertificadoBase64() throws Exception {
        InputStream certStream = getClass().getClassLoader().getResourceAsStream(CSD_CERT_PATH);
        if (certStream == null) {
            throw new FileNotFoundException("Certificate file not found: " + CSD_CERT_PATH);
        }

        byte[] certBytes = IOUtils.toByteArray(certStream);
        return Base64.getEncoder().encodeToString(certBytes);
    }

    private String extraerNumeroCertificado() throws Exception {
        InputStream certStream = getClass().getClassLoader().getResourceAsStream(CSD_CERT_PATH);
        if (certStream == null) {
            throw new FileNotFoundException("Certificate file not found: " + CSD_CERT_PATH);
        }

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(certStream);
        return String.format("%020d", cert.getSerialNumber());
    }
}