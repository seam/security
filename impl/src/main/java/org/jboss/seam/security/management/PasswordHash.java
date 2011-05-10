package org.jboss.seam.security.management;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.enterprise.context.Dependent;
import javax.inject.Named;

import org.jboss.seam.security.crypto.BinTools;
import org.jboss.seam.security.crypto.PBKDF2;
import org.jboss.seam.security.crypto.PBKDF2Engine;
import org.jboss.seam.security.crypto.PBKDF2Parameters;
import org.jboss.seam.security.util.Base64;

/**
 * Password hashing utility functions
 *
 * @author Shane Bryzak
 */
@Named
@Dependent
public class PasswordHash {
    public static final String ALGORITHM_MD5 = "MD5";
    public static final String ALGORITHM_SHA = "SHA";

    private static final String DEFAULT_ALGORITHM = ALGORITHM_MD5;

    /*
    * If specified, use the JCE instead of the built in algorithm
    */
    private String hashAlgorithm = null;

    /*
    *  default password salt length, in bytes
    */
    private int saltLength = 8;

    @Deprecated
    public String generateHash(String password) {
        return generateHash(password, DEFAULT_ALGORITHM);
    }

    @Deprecated
    public String generateHash(String password, String algorithm) {
        return generateSaltedHash(password, null, algorithm);
    }

    @Deprecated
    public String generateSaltedHash(String password, String saltPhrase) {
        return generateSaltedHash(password, saltPhrase, DEFAULT_ALGORITHM);
    }

    /**
     * @deprecated Use PasswordHash.createPasswordKey() instead
     */
    @Deprecated
    public String generateSaltedHash(String password, String saltPhrase, String algorithm) {
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);

            if (saltPhrase != null) {
                md.update(saltPhrase.getBytes());
                byte[] salt = md.digest();

                md.reset();
                md.update(password.getBytes());
                md.update(salt);
            } else {
                md.update(password.getBytes());
            }

            byte[] raw = md.digest();
            return Base64.encodeBytes(raw);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] generateRandomSalt() {
        byte[] salt = new byte[saltLength];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    /**
     *
     */
    public String createPasswordKey(char[] password, byte[] salt, int iterations)
            throws GeneralSecurityException {
        if (hashAlgorithm != null) {
            PBEKeySpec passwordKeySpec = new PBEKeySpec(password, salt, iterations, 256);
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(hashAlgorithm);
            SecretKey passwordKey = secretKeyFactory.generateSecret(passwordKeySpec);
            passwordKeySpec.clearPassword();
            return BinTools.bin2hex(passwordKey.getEncoded());
        } else {
            PBKDF2Parameters params = new PBKDF2Parameters("HmacSHA1", "ISO-8859-1", salt, iterations);
            PBKDF2 pbkdf2 = new PBKDF2Engine(params);
            return BinTools.bin2hex(pbkdf2.deriveKey(new String(password)));
        }
    }

    public String getHashAlgorithm() {
        return hashAlgorithm;
    }

    public void setHashAlgorithm(String hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
    }

    public int getSaltLength() {
        return saltLength;
    }

    public void setSaltLength(int saltLength) {
        this.saltLength = saltLength;
    }
}
