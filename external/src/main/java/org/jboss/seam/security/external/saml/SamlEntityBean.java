package org.jboss.seam.security.external.saml;

import java.io.Reader;
import java.io.Writer;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.inject.Inject;
import javax.servlet.ServletContext;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.jboss.seam.security.external.EntityBean;
import org.jboss.seam.security.external.JaxbContext;
import org.jboss.seam.security.external.jaxb.samlv2.metadata.EntitiesDescriptorType;
import org.jboss.seam.security.external.jaxb.samlv2.metadata.EntityDescriptorType;
import org.jboss.seam.security.external.jaxb.samlv2.metadata.IndexedEndpointType;
import org.jboss.seam.security.external.jaxb.samlv2.metadata.KeyDescriptorType;
import org.jboss.seam.security.external.jaxb.samlv2.metadata.KeyTypes;
import org.jboss.seam.security.external.jaxb.samlv2.metadata.ObjectFactory;
import org.jboss.seam.security.external.jaxb.samlv2.metadata.RoleDescriptorType;
import org.jboss.seam.security.external.jaxb.samlv2.metadata.SSODescriptorType;
import org.jboss.seam.security.external.jaxb.xmldsig.KeyInfoType;
import org.jboss.seam.security.external.jaxb.xmldsig.X509DataType;
import org.jboss.seam.security.external.saml.api.SamlBinding;
import org.jboss.seam.security.external.saml.api.SamlEntityConfigurationApi;

/**
 * @author Marcel Kolsteren
 */
public abstract class SamlEntityBean extends EntityBean implements SamlEntityConfigurationApi {
    private Map<String, SSODescriptorType> metaInfo = new HashMap<String, SSODescriptorType>();

    private String entityId;

    private SamlSigningKey samlSigningKey;

    private SamlBinding preferredBinding = SamlBinding.HTTP_Post;

    @Inject
    private ServletContext servletContext;

    @Inject
    @JaxbContext(ObjectFactory.class)
    protected JAXBContext metaDataJaxbContext;

    private boolean singleLogoutMessagesSigned = true;

    private boolean wantSingleLogoutMessagesSigned = true;

    public String getServiceURL(SamlServiceType service) {
        return createURL(servletContext.getContextPath() + "/saml/" + getIdpOrSp() + "/" + service.getName());
    }

    public String getMetaDataURL() {
        return getServiceURL(SamlServiceType.SAML_META_DATA_SERVICE);
    }

    public void setEntityId(String entityId) {
        this.entityId = entityId;
    }

    public String getEntityId() {
        return entityId;
    }

    protected SamlSigningKey getSigningKey() {
        return samlSigningKey;
    }

    public void setSigningKey(String keyStoreUrl, String keyStorePass, String signingKeyAlias, String signingKeyPass) {
        if (signingKeyPass == null) {
            signingKeyPass = keyStorePass;
        }
        samlSigningKey = new SamlSigningKey(keyStoreUrl, keyStorePass, signingKeyAlias, signingKeyPass);
    }

    public boolean isSingleLogoutMessagesSigned() {
        return singleLogoutMessagesSigned;
    }

    public void setSingleLogoutMessagesSigned(boolean singleLogoutMessagesSigned) {
        this.singleLogoutMessagesSigned = singleLogoutMessagesSigned;
    }

    public boolean isWantSingleLogoutMessagesSigned() {
        return wantSingleLogoutMessagesSigned;
    }

    public void setWantSingleLogoutMessagesSigned(boolean wantSingleLogoutMessagesSigned) {
        this.wantSingleLogoutMessagesSigned = wantSingleLogoutMessagesSigned;
    }

    public abstract SamlIdpOrSp getIdpOrSp();

    public abstract SamlExternalEntity getExternalSamlEntityByEntityId(String entityId);

    public abstract SamlExternalEntity addExternalSamlEntity(Reader reader);

    public abstract List<SamlExternalEntity> getExternalSamlEntities();

    protected void readEntitiesDescriptor(Reader reader) {
        try {
            Unmarshaller unmarshaller = metaDataJaxbContext.createUnmarshaller();
            JAXBElement<?> o = (JAXBElement<?>) unmarshaller.unmarshal(reader);
            EntitiesDescriptorType entitiesDescriptor = (EntitiesDescriptorType) o.getValue();
            readEntitiesDescriptor(entitiesDescriptor);
        } catch (JAXBException e) {
            throw new RuntimeException(e);
        }
    }

    private void readEntitiesDescriptor(EntitiesDescriptorType entitiesDescriptor) {
        for (Object object : entitiesDescriptor.getEntityDescriptorOrEntitiesDescriptor()) {
            if (object instanceof EntityDescriptorType) {
                EntityDescriptorType entityDescriptor = (EntityDescriptorType) object;
                readEntityDescriptor(entityDescriptor);
            } else {
                EntitiesDescriptorType descriptor = (EntitiesDescriptorType) object;
                readEntitiesDescriptor(descriptor);
            }
        }
    }

    private void readEntityDescriptor(EntityDescriptorType entityDescriptor) {
        String entityId = entityDescriptor.getEntityID();

        for (RoleDescriptorType roleDescriptor : entityDescriptor.getRoleDescriptorOrIDPSSODescriptorOrSPSSODescriptor()) {
            metaInfo.put(entityId, (SSODescriptorType) roleDescriptor);
        }
    }

    public Map<String, SSODescriptorType> getMetaInfo() {
        return metaInfo;
    }

    protected EntityDescriptorType readEntityDescriptor(Reader metaInfoReader) {
        try {
            Unmarshaller unmarshaller = metaDataJaxbContext.createUnmarshaller();
            JAXBElement<?> o = (JAXBElement<?>) unmarshaller.unmarshal(metaInfoReader);
            EntityDescriptorType entityDescriptor = (EntityDescriptorType) o.getValue();
            return entityDescriptor;
        } catch (JAXBException e) {
            throw new RuntimeException(e);
        }
    }

    public abstract void writeMetaData(Writer writer);

    protected void addKeyDescriptorToMetaData(SSODescriptorType ssoDescriptor) {
        ObjectFactory metaDataFactory = new ObjectFactory();
        org.jboss.seam.security.external.jaxb.xmldsig.ObjectFactory signatureFactory = new org.jboss.seam.security.external.jaxb.xmldsig.ObjectFactory();

        X509Certificate certificate = getSigningKey().getCertificate();
        if (certificate == null)
            throw new RuntimeException("Certificate obtained from configuration is null");

        JAXBElement<byte[]> X509Certificate;
        try {
            X509Certificate = signatureFactory.createX509DataTypeX509Certificate(certificate.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new RuntimeException(e);
        }

        X509DataType X509Data = signatureFactory.createX509DataType();
        X509Data.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(X509Certificate);

        KeyInfoType keyInfo = signatureFactory.createKeyInfoType();
        keyInfo.getContent().add(signatureFactory.createX509Data(X509Data));

        KeyDescriptorType keyDescriptor = metaDataFactory.createKeyDescriptorType();
        keyDescriptor.setUse(KeyTypes.SIGNING);
        keyDescriptor.setKeyInfo(keyInfo);

        ssoDescriptor.getKeyDescriptor().add(keyDescriptor);
    }

    protected void addSloEndpointsToMetaData(SSODescriptorType ssoDescriptor) {
        ObjectFactory metaDataFactory = new ObjectFactory();

        IndexedEndpointType sloRedirectEndpoint = metaDataFactory.createIndexedEndpointType();
        sloRedirectEndpoint.setBinding(SamlConstants.HTTP_REDIRECT_BINDING);
        sloRedirectEndpoint.setLocation(getServiceURL(SamlServiceType.SAML_SINGLE_LOGOUT_SERVICE));

        IndexedEndpointType sloPostEndpoint = metaDataFactory.createIndexedEndpointType();
        sloPostEndpoint.setBinding(SamlConstants.HTTP_POST_BINDING);
        sloPostEndpoint.setLocation(getServiceURL(SamlServiceType.SAML_SINGLE_LOGOUT_SERVICE));

        ssoDescriptor.getSingleLogoutService().add(sloRedirectEndpoint);
        ssoDescriptor.getSingleLogoutService().add(sloPostEndpoint);
    }

    protected void addNameIDFormatsToMetaData(SSODescriptorType idpSsoDescriptor) {
        idpSsoDescriptor.getNameIDFormat().add("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
        idpSsoDescriptor.getNameIDFormat().add("urn:oasis:names:tc:SAML:2.0:nameid-format:transient");
        idpSsoDescriptor.getNameIDFormat().add("urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified");
        idpSsoDescriptor.getNameIDFormat().add("urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress");
    }

    public SamlBinding getPreferredBinding() {
        return preferredBinding;
    }

    public void setPreferredBinding(SamlBinding preferredBinding) {
        this.preferredBinding = preferredBinding;
    }
}
