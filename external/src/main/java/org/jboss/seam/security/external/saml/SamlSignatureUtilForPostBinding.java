package org.jboss.seam.security.external.saml;

import java.security.AccessController;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PrivilegedAction;
import java.security.PublicKey;
import java.security.Security;
import java.util.Collections;
import java.util.List;

import javax.inject.Inject;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;

import org.jboss.solder.logging.Logger;
import org.jboss.seam.security.external.InvalidRequestException;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

/**
 * @author Marcel Kolsteren
 */
public class SamlSignatureUtilForPostBinding {
    private final static Logger log = Logger.getLogger(SamlSignatureUtilForPostBinding.class);

    private XMLSignatureFactory fac;

    @Inject
    public void init() {
        AccessController.doPrivileged(new PrivilegedAction<Object>() {
            public Object run() {
                System.setProperty("org.apache.xml.security.ignoreLineBreaks", "true");
                return null;
            }
        });
        fac = getXMLSignatureFactory();
    }

    ;

    private XMLSignatureFactory getXMLSignatureFactory() {
        if (Security.getProvider("DOM") != null) {
            return XMLSignatureFactory.getInstance("DOM");
        } else {
            // No security provider found for the XML Digital Signature API (JSR
            // 105). Probably we have to do with JDK 1.5 or lower.
            // See
            // http://weblogs.java.net/blog/2008/02/27/using-jsr-105-jdk-14-or-15.
            // We assume that the reference implementation of JSR 105 is available
            // at runtime.
            return XMLSignatureFactory.getInstance("DOM", new org.jcp.xml.dsig.internal.dom.XMLDSigRI());
        }
    }

    public Document sign(Document doc, KeyPair keyPair) {
        if (log.isTraceEnabled()) {
            log.tracef("Document to be signed={0}", new Object[]{SamlUtils.getDocumentAsString(doc)});
        }

        PrivateKey signingKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        DOMSignContext dsc = new DOMSignContext(signingKey, doc.getDocumentElement());
        dsc.setDefaultNamespacePrefix("dsig");

        try {
            DigestMethod digestMethodObj = fac.newDigestMethod(DigestMethod.SHA1, null);
            Transform transform = fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null);

            List<Transform> transformList = Collections.singletonList(transform);
            String referenceURI = "#" + doc.getDocumentElement().getAttribute("ID");
            Reference ref = fac.newReference(referenceURI, digestMethodObj, transformList, null, null);

            String canonicalizationMethodType = CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS;
            CanonicalizationMethod canonicalizationMethod = fac.newCanonicalizationMethod(canonicalizationMethodType, (C14NMethodParameterSpec) null);

            List<Reference> referenceList = Collections.singletonList(ref);

            String signatureMethodString = publicKey.getAlgorithm().equalsIgnoreCase("RSA") ? SignatureMethod.RSA_SHA1 : SignatureMethod.DSA_SHA1;
            SignatureMethod signatureMethod = fac.newSignatureMethod(signatureMethodString, null);
            SignedInfo si = fac.newSignedInfo(canonicalizationMethod, signatureMethod, referenceList);

            KeyInfoFactory kif = fac.getKeyInfoFactory();
            KeyValue kv = kif.newKeyValue(publicKey);
            KeyInfo ki = kif.newKeyInfo(Collections.singletonList(kv));

            XMLSignature signature = fac.newXMLSignature(si, ki);

            signature.sign(dsc);
        } catch (XMLSignatureException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        } catch (KeyException e) {
            throw new RuntimeException(e);
        } catch (MarshalException e) {
            throw new RuntimeException(e);

        }
        return doc;
    }

    public void validateSignature(Key publicKey, Document signedDoc) throws InvalidRequestException {
        NodeList nl = signedDoc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        if (nl == null || nl.getLength() == 0) {
            throw new InvalidRequestException("Signature element is not present or has zero length.");
        }

        try {
            DOMValidateContext valContext = new DOMValidateContext(publicKey, nl.item(0));
            XMLSignature signature = fac.unmarshalXMLSignature(valContext);
            boolean signatureValid = signature.validate(valContext);

            if (log.isTraceEnabled() && !signatureValid) {
                boolean sv = signature.getSignatureValue().validate(valContext);
                log.trace("Signature validation status: " + sv);

                @SuppressWarnings("unchecked")
                List<Reference> references = signature.getSignedInfo().getReferences();
                for (Reference ref : references) {
                    log.trace("[Ref id=" + ref.getId() + ":uri=" + ref.getURI() + "] validity status:" + ref.validate(valContext));
                }
            }

            if (!signatureValid) {
                throw new InvalidRequestException("Invalid signature.");
            }
        } catch (XMLSignatureException e) {
            throw new RuntimeException(e);
        } catch (MarshalException e) {
            throw new RuntimeException(e);
        }
    }
}
