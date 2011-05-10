package org.jboss.seam.security.externaltest.module;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.xml.parsers.ParserConfigurationException;

import junit.framework.Assert;
import org.jboss.seam.security.external.Base64;
import org.jboss.seam.security.external.InvalidRequestException;
import org.jboss.seam.security.external.saml.SamlRedirectMessage;
import org.jboss.seam.security.external.saml.SamlRequestOrResponse;
import org.jboss.seam.security.external.saml.SamlSignatureUtilForRedirectBinding;
import org.junit.Before;
import org.junit.Test;

public class SamlSignatureUtilForRedirectBindingTest {
    private SamlSignatureUtilForRedirectBinding samlSignatureUtilForRedirectBinding;

    private KeyPair keyPair;

    @Before
    public void setup() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException {
        samlSignatureUtilForRedirectBinding = new SamlSignatureUtilForRedirectBinding();

        // Get private and public key
        InputStream keyStoreStream = getClass().getClassLoader().getResourceAsStream("test_keystore.jks");
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(keyStoreStream, "store456".toCharArray());
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate("servercert");
        PublicKey publicKey = certificate.getPublicKey();
        PrivateKey privateKey = (PrivateKey) keyStore.getKey("servercert", "pass456".toCharArray());
        keyPair = new KeyPair(publicKey, privateKey);
    }

    @Test
    public void testValidSignature() throws ParserConfigurationException, InvalidRequestException, IOException, GeneralSecurityException {
        SamlRedirectMessage samlRedirectMessage = createSignedRedirectMessage();

        // Verify the signature (must not throw an InvalidRequestException)
        samlSignatureUtilForRedirectBinding.validateSignature(samlRedirectMessage, keyPair.getPublic());
    }

    @Test
    public void testInvalidSignature() throws ParserConfigurationException {
        SamlRedirectMessage samlRedirectMessage = createSignedRedirectMessage();

        // Modify the message contents
        samlRedirectMessage.setRelayState("bar");

        // Verify the signature. Verification must fail.
        boolean exception = false;
        try {
            samlSignatureUtilForRedirectBinding.validateSignature(samlRedirectMessage, keyPair.getPublic());
        } catch (InvalidRequestException e) {
            exception = true;
        }

        Assert.assertTrue(exception);
    }

    private SamlRedirectMessage createSignedRedirectMessage() {
        SamlRedirectMessage samlRedirectMessage = new SamlRedirectMessage();
        String base64EncodedMessage = Base64.encodeBytes("this is just a test string".getBytes(), Base64.DONT_BREAK_LINES);
        samlRedirectMessage.setRequestOrResponse(SamlRequestOrResponse.REQUEST);
        samlRedirectMessage.setSamlMessage(base64EncodedMessage);
        samlRedirectMessage.setRelayState("foo");
        samlRedirectMessage.encode();
        try {
            samlSignatureUtilForRedirectBinding.sign(samlRedirectMessage, keyPair.getPrivate());
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
        return samlRedirectMessage;
    }
}
