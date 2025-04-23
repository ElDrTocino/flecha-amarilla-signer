package org.flechaamarilla.service;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.annotation.PostConstruct;
import org.apache.commons.io.IOUtils;
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

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.LocalDateTime;
import java.util.Base64;
import org.jboss.logging.Logger;

@ApplicationScoped
public class SignerService {

    private static final String XSLT_PATH = "cadenaoriginal_3_3.xslt";
    private static final String CSD_KEY_PATH = "csd-pkcs8.key";
    private static final String CSD_KEY_PASS = "12345678a";
    private static final String CSD_CERT_PATH = "CSD_Pruebas_CFDI_SPR190613I52.cer";
    private static final Logger LOG = Logger.getLogger(SignerService.class);
    
    // Caché para transformador XSLT
    private static Transformer cachedTransformer;
    
    // Caché para llave privada
    private static PrivateKey cachedPrivateKey;
    
    // Caché para certificado en Base64
    private static String cachedCertificadoBase64;
    
    // Caché para número de certificado
    private static String cachedNumeroCertificado;
    
    // Tiempo de la última actualización del caché
    private static LocalDateTime lastCacheRefresh;
    
    // Tiempo de expiración del caché en horas (configurable)
    private static final long CACHE_EXPIRATION_HOURS = 24;

    @PostConstruct
    public void init() {
        try {
            // Inicialización de caché al arrancar el servicio
            refreshCache();
            LOG.info("Caché de recursos inicializado exitosamente.");
        } catch (Exception e) {
            LOG.error("Error al inicializar caché de recursos", e);
        }
    }
    
    /**
     * Refresca todos los recursos en caché
     */
    public synchronized void refreshCache() throws Exception {
        LOG.info("Refrescando recursos en caché...");
        // Registrar proveedor BouncyCastle si no está registrado
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        
        // Cargar transformador XSLT
        InputStream xsltStream = getClass().getClassLoader().getResourceAsStream(XSLT_PATH);
        if (xsltStream == null) {
            throw new FileNotFoundException("XSLT resource not found: " + XSLT_PATH);
        }
        TransformerFactory tf = TransformerFactory.newInstance();
        cachedTransformer = tf.newTransformer(new StreamSource(xsltStream));
        xsltStream.close();
        
        // Cargar llave privada
        cachedPrivateKey = cargarLlavePrivadaDesdeRecurso();
        
        // Cargar certificado en Base64
        cachedCertificadoBase64 = cargarCertificadoBase64Desde();
        
        // Extraer número de certificado
        cachedNumeroCertificado = extraerNumeroCertificadoDesdeRecurso();
        
        // Actualizar timestamp
        lastCacheRefresh = LocalDateTime.now();
        LOG.info("Caché de recursos actualizado");
    }
    
    /**
     * Verifica si el caché ha expirado
     */
    private boolean isCacheExpired() {
        if (lastCacheRefresh == null) {
            return true;
        }
        return lastCacheRefresh.plusHours(CACHE_EXPIRATION_HOURS).isBefore(LocalDateTime.now());
    }
    
    /**
     * Verifica y actualiza el caché si es necesario
     */
    private void checkAndRefreshCache() throws Exception {
        if (cachedTransformer == null || cachedPrivateKey == null || 
            cachedCertificadoBase64 == null || cachedNumeroCertificado == null || 
            isCacheExpired()) {
            refreshCache();
        }
    }

    public String signXml(String xml) throws Exception {
        // Verificar y refrescar caché si es necesario
        checkAndRefreshCache();
        
        String cadenaOriginal = generarCadenaOriginal(xml);
        String sello = generarSelloDigital(cadenaOriginal);
        
        // Usar valores cacheados
        String certificado = cachedCertificadoBase64;
        String noCertificado = cachedNumeroCertificado;

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
        // Usar transformador cacheado
        StringWriter writer = new StringWriter();
        cachedTransformer.transform(new StreamSource(new StringReader(xml)), new StreamResult(writer));
        return writer.toString();
    }

    private String generarSelloDigital(String cadenaOriginal) throws Exception {
        // Usar llave privada cacheada
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(cachedPrivateKey);
        signature.update(cadenaOriginal.getBytes(StandardCharsets.UTF_8));
        byte[] signed = signature.sign();
        return Base64.getEncoder().encodeToString(signed);
    }

    /**
     * Carga la llave privada desde el recurso (usado solo para el caché)
     */
    private PrivateKey cargarLlavePrivadaDesdeRecurso() throws Exception {
        InputStream keyStream = getClass().getClassLoader().getResourceAsStream(CSD_KEY_PATH);
        if (keyStream == null) {
            throw new FileNotFoundException("Key file not found: " + CSD_KEY_PATH);
        }

        byte[] keyBytes = IOUtils.toByteArray(keyStream);
        keyStream.close();

        try {
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

    // El método original se mantiene por compatibilidad pero redirige al caché
    private PrivateKey cargarLlavePrivada() throws Exception {
        checkAndRefreshCache();
        return cachedPrivateKey;
    }

    /**
     * Carga el certificado en Base64 desde el recurso (usado solo para el caché)
     */
    private String cargarCertificadoBase64Desde() throws Exception {
        InputStream certStream = getClass().getClassLoader().getResourceAsStream(CSD_CERT_PATH);
        if (certStream == null) {
            throw new FileNotFoundException("Certificate file not found: " + CSD_CERT_PATH);
        }

        byte[] certBytes = IOUtils.toByteArray(certStream);
        certStream.close();
        return Base64.getEncoder().encodeToString(certBytes);
    }

    // El método original se mantiene por compatibilidad pero redirige al caché
    private String cargarCertificadoBase64() throws Exception {
        checkAndRefreshCache();
        return cachedCertificadoBase64;
    }

    /**
     * Extrae el número de certificado desde el recurso (usado solo para el caché)
     */
    private String extraerNumeroCertificadoDesdeRecurso() throws Exception {
        InputStream certStream = getClass().getClassLoader().getResourceAsStream(CSD_CERT_PATH);
        if (certStream == null) {
            throw new FileNotFoundException("Certificate file not found: " + CSD_CERT_PATH);
        }

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(certStream);
        certStream.close();
        return String.format("%020d", cert.getSerialNumber());
    }

    // El método original se mantiene por compatibilidad pero redirige al caché
    private String extraerNumeroCertificado() throws Exception {
        checkAndRefreshCache();
        return cachedNumeroCertificado;
    }
}