package org.jboss.seam.security.external.saml;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * @author Marcel Kolsteren
 */
public class SamlSigningKey {
    private PrivateKey privateKey;

    private X509Certificate certificate;

    public SamlSigningKey(String keyStoreUrl, String keyStorePass, String signingKeyAlias, String signingKeyPass) {
        if (signingKeyPass == null) {
            signingKeyPass = keyStorePass;
        }
        getSigningKeyPair(keyStoreUrl, keyStorePass, signingKeyAlias, signingKeyPass);
    }

    private void getSigningKeyPair(String keyStoreUrl, String keyStorePass, String signingKeyAlias, String signingKeyPass) {
        final String classPathPrefix = "classpath:";

        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            InputStream keyStoreStream;
            if (keyStoreUrl.startsWith(classPathPrefix)) {
                keyStoreStream = getClass().getResourceAsStream(keyStoreUrl.substring(classPathPrefix.length()));
                if (keyStoreStream == null) {
                    throw new RuntimeException("Keystore " + keyStoreUrl + " could not be loaded from the classpath.");
                }
            } else {
                keyStoreStream = new URL(keyStoreUrl).openStream();
            }
            char[] keyStorePwd = keyStorePass != null ? keyStorePass.toCharArray() : null;
            keyStore.load(keyStoreStream, keyStorePwd);

            certificate = (X509Certificate) keyStore.getCertificate(signingKeyAlias);

            char[] signingKeyPwd = signingKeyPass != null ? signingKeyPass.toCharArray() : null;

            privateKey = (PrivateKey) keyStore.getKey(signingKeyAlias, signingKeyPwd);

            if (privateKey == null) {
                throw new RuntimeException("Key with alias " + signingKeyAlias + " was not found in keystore " + keyStoreUrl);
            }
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (UnrecoverableKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }
}
