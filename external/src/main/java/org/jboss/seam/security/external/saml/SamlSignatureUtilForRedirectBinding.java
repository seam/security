package org.jboss.seam.security.external.saml;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import javax.xml.crypto.dsig.SignatureMethod;

import org.jboss.seam.security.external.Base64;
import org.jboss.seam.security.external.InvalidRequestException;

/**
 * @author Marcel Kolsteren
 */
public class SamlSignatureUtilForRedirectBinding {
    public void sign(SamlRedirectMessage urlEncodedRedirectMessage, PrivateKey signingKey) throws IOException, GeneralSecurityException {
        urlEncodedRedirectMessage.setSignatureAlgorithm(getXMLSignatureAlgorithmURI(signingKey.getAlgorithm()));

        byte[] signature = computeSignature(urlEncodedRedirectMessage.createQueryString(), signingKey);

        String base64encodedSignature = Base64.encodeBytes(signature, Base64.DONT_BREAK_LINES);

        String urlEncodedSignature = URLEncoder.encode(base64encodedSignature, "UTF-8");

        urlEncodedRedirectMessage.setSignature(urlEncodedSignature);
    }

    private byte[] computeSignature(String stringToBeSigned, PrivateKey signingKey) throws GeneralSecurityException {
        String algo = signingKey.getAlgorithm();
        Signature sig = getSignature(algo);
        sig.initSign(signingKey);
        sig.update(stringToBeSigned.getBytes());
        return sig.sign();
    }

    public void validateSignature(SamlRedirectMessage urlEncodedRedirectMessage, PublicKey publicKey) throws InvalidRequestException {
        if (urlEncodedRedirectMessage.getSignature() == null) {
            throw new InvalidRequestException("Signature parameter is not present.");
        }

        String urlDecodedSignature;
        try {
            urlDecodedSignature = URLDecoder.decode(urlEncodedRedirectMessage.getSignature(), "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }

        byte[] base64DecodedSignature = Base64.decode(urlDecodedSignature);

        // Reconstruct the string that has been signed by the other party
        SamlRedirectMessage signedRedirectMessage = new SamlRedirectMessage();
        signedRedirectMessage.setRequestOrResponse(urlEncodedRedirectMessage.getRequestOrResponse());
        signedRedirectMessage.setSamlMessage(urlEncodedRedirectMessage.getSamlMessage());
        signedRedirectMessage.setRelayState(urlEncodedRedirectMessage.getRelayState());
        signedRedirectMessage.setSignatureAlgorithm(urlEncodedRedirectMessage.getSignatureAlgorithm());
        signedRedirectMessage.setUrlEncoded(true);
        String signedString = signedRedirectMessage.createQueryString();

        boolean isValid;
        try {
            isValid = validate(signedString.getBytes("UTF-8"), base64DecodedSignature, publicKey);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }

        if (!isValid) {
            throw new InvalidRequestException("Invalid signature.");
        }
    }

    private boolean validate(byte[] signedContent, byte[] signatureValue, PublicKey validatingKey) throws GeneralSecurityException {
        String algo = validatingKey.getAlgorithm();
        Signature sig = getSignature(algo);

        sig.initVerify(validatingKey);
        sig.update(signedContent);
        return sig.verify(signatureValue);
    }

    private Signature getSignature(String algo) throws GeneralSecurityException {
        Signature sig = null;

        if ("DSA".equalsIgnoreCase(algo)) {
            sig = Signature.getInstance(SamlConstants.DSA_SIGNATURE_ALGORITHM);
        } else if ("RSA".equalsIgnoreCase(algo)) {
            sig = Signature.getInstance(SamlConstants.RSA_SIGNATURE_ALGORITHM);
        } else
            throw new RuntimeException("Unknown signature algorithm:" + algo);
        return sig;
    }

    private String getXMLSignatureAlgorithmURI(String algo) {
        String xmlSignatureAlgo = null;

        if ("DSA".equalsIgnoreCase(algo)) {
            xmlSignatureAlgo = SignatureMethod.DSA_SHA1;
        } else if ("RSA".equalsIgnoreCase(algo)) {
            xmlSignatureAlgo = SignatureMethod.RSA_SHA1;
        }
        return xmlSignatureAlgo;
    }
}
