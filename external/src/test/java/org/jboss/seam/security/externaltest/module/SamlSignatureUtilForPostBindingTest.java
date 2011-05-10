package org.jboss.seam.security.externaltest.module;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import junit.framework.Assert;
import org.jboss.seam.security.external.InvalidRequestException;
import org.jboss.seam.security.external.saml.SamlSignatureUtilForPostBinding;
import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class SamlSignatureUtilForPostBindingTest {
    private SamlSignatureUtilForPostBinding samlSignatureUtilForPostBinding;

    private KeyPair keyPair;

    @Before
    public void setup() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException {
        samlSignatureUtilForPostBinding = new SamlSignatureUtilForPostBinding();

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
    public void testValidSignature() throws ParserConfigurationException, InvalidRequestException {
        Document doc = createSignedDocument();

        // Verify the signature (must not throw an InvalidRequestException)
        samlSignatureUtilForPostBinding.validateSignature(keyPair.getPublic(), doc);
    }

    @Test
    public void testInvalidSignature() throws ParserConfigurationException {
        Document doc = createSignedDocument();

        // Manipulate the document
        Element root = doc.getElementById("rootElement");
        root.setAttribute("extraAttribute", "value");

        // Verify the signature. Verification must fail.
        boolean exception = false;
        try {
            samlSignatureUtilForPostBinding.validateSignature(keyPair.getPublic(), doc);
        } catch (InvalidRequestException e) {
            exception = true;
        }

        Assert.assertTrue(exception);
    }

    private Document createSignedDocument() throws ParserConfigurationException {
        // Create a test document
        DocumentBuilderFactory dbfac = DocumentBuilderFactory.newInstance();
        DocumentBuilder docBuilder = dbfac.newDocumentBuilder();
        Document doc = docBuilder.newDocument();
        Element root = doc.createElement("root");
        root.setAttribute("ID", "rootElement");
        root.setIdAttribute("ID", true);
        doc.appendChild(root);
        Element child = doc.createElement("child");
        child.setAttribute("name", "value");
        root.appendChild(child);

        // Sign the document
        samlSignatureUtilForPostBinding.init();
        samlSignatureUtilForPostBinding.sign(doc, keyPair);

        return doc;
    }
}
