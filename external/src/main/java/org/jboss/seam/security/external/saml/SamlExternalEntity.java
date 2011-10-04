package org.jboss.seam.security.external.saml;

import java.security.PublicKey;
import java.util.List;

import javax.security.cert.X509Certificate;
import javax.xml.bind.JAXBElement;

import org.jboss.seam.security.external.jaxb.samlv2.metadata.KeyDescriptorType;
import org.jboss.seam.security.external.jaxb.samlv2.metadata.KeyTypes;
import org.jboss.seam.security.external.jaxb.xmldsig.X509DataType;

/**
 * @author Marcel Kolsteren
 */
public abstract class SamlExternalEntity {

    private String entityId;

    private PublicKey publicKey;

    public SamlExternalEntity(String entityId, List<KeyDescriptorType> keyDescriptors) {
        super();
        this.entityId = entityId;
        setPublicKey(keyDescriptors);
    }

    public String getEntityId() {
        return entityId;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    private void setPublicKey(List<KeyDescriptorType> keyDescriptors) {
        for (KeyDescriptorType keyDescriptor : keyDescriptors) {
            if (keyDescriptor.getUse().equals(KeyTypes.SIGNING)) {
                for (Object content : keyDescriptor.getKeyInfo().getContent()) {
                    if (content instanceof JAXBElement<?> && ((JAXBElement<?>) content).getValue() instanceof X509DataType) {
                        X509DataType X509Data = (X509DataType) ((JAXBElement<?>) content).getValue();
                        for (Object object : X509Data.getX509IssuerSerialOrX509SKIOrX509SubjectName()) {
                            if (object instanceof JAXBElement<?>) {
                                JAXBElement<?> el = (JAXBElement<?>) object;
                                if (el.getName().getLocalPart().equals("X509Certificate")) {
                                    byte[] certificate = (byte[]) el.getValue();
                                    try {
                                        X509Certificate cert = X509Certificate.getInstance(certificate);
                                        publicKey = cert.getPublicKey();
                                    } catch (javax.security.cert.CertificateException e) {
                                        throw new RuntimeException(e);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    public abstract SamlService getService(SamlProfile service);

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((entityId == null) ? 0 : entityId.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        SamlExternalEntity other = (SamlExternalEntity) obj;
        if (entityId == null) {
            if (other.entityId != null)
                return false;
        } else if (!entityId.equals(other.entityId))
            return false;
        return true;
    }
}
