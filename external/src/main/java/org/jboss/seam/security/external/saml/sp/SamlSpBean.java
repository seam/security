package org.jboss.seam.security.external.saml.sp;

import java.io.Reader;
import java.io.Writer;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import javax.enterprise.inject.Typed;
import javax.inject.Inject;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import org.jboss.seam.security.external.SamlMultiUserServiceProviderApi;
import org.jboss.seam.security.external.dialogues.api.Dialogued;
import org.jboss.seam.security.external.jaxb.samlv2.metadata.EntityDescriptorType;
import org.jboss.seam.security.external.jaxb.samlv2.metadata.IDPSSODescriptorType;
import org.jboss.seam.security.external.jaxb.samlv2.metadata.IndexedEndpointType;
import org.jboss.seam.security.external.jaxb.samlv2.metadata.ObjectFactory;
import org.jboss.seam.security.external.jaxb.samlv2.metadata.SPSSODescriptorType;
import org.jboss.seam.security.external.saml.SamlConstants;
import org.jboss.seam.security.external.saml.SamlEntityBean;
import org.jboss.seam.security.external.saml.SamlExternalEntity;
import org.jboss.seam.security.external.saml.SamlIdpOrSp;
import org.jboss.seam.security.external.saml.SamlServiceType;
import org.jboss.seam.security.external.saml.api.SamlServiceProviderConfigurationApi;
import org.jboss.seam.security.external.saml.api.SamlSpSession;

/**
 * @author Marcel Kolsteren
 */
@Typed(SamlSpBean.class)
public class SamlSpBean extends SamlEntityBean implements SamlSpBeanApi, SamlMultiUserServiceProviderApi, SamlServiceProviderConfigurationApi {
    private List<SamlExternalIdentityProvider> identityProviders = new LinkedList<SamlExternalIdentityProvider>();

    @Inject
    private SamlSpSingleSignOnService samlSpSingleSignOnService;

    @Inject
    private SamlSpSingleLogoutService samlSpSingleLogoutService;

    @Inject
    private SamlSpSessions samlSpSessions;

    private boolean authnRequestsSigned = false;

    private boolean wantAssertionsSigned = false;

    public SamlExternalIdentityProvider addExternalIdentityProvider(String entityId, IDPSSODescriptorType idpSsoDescriptor) {
        SamlExternalIdentityProvider samlIdentityProvider = new SamlExternalIdentityProvider(entityId, idpSsoDescriptor);
        identityProviders.add(samlIdentityProvider);
        return samlIdentityProvider;
    }

    public SamlExternalIdentityProvider addExternalSamlEntity(Reader reader) {
        EntityDescriptorType entityDescriptor = readEntityDescriptor(reader);
        String entityId = entityDescriptor.getEntityID();
        IDPSSODescriptorType IDPSSODescriptor = (IDPSSODescriptorType) entityDescriptor.getRoleDescriptorOrIDPSSODescriptorOrSPSSODescriptor().get(0);
        return addExternalIdentityProvider(entityId, IDPSSODescriptor);
    }

    @Override
    public List<SamlExternalEntity> getExternalSamlEntities() {
        List<SamlExternalEntity> samlEntities = new LinkedList<SamlExternalEntity>();
        for (SamlExternalIdentityProvider idp : identityProviders) {
            samlEntities.add(idp);
        }
        return samlEntities;
    }

    public List<SamlExternalIdentityProvider> getIdentityProviders() {
        return identityProviders;
    }

    public boolean isAuthnRequestsSigned() {
        return authnRequestsSigned;
    }

    public void setAuthnRequestsSigned(boolean authnRequestsSigned) {
        this.authnRequestsSigned = authnRequestsSigned;
    }

    public boolean isWantAssertionsSigned() {
        return wantAssertionsSigned;
    }

    public void setWantAssertionsSigned(boolean wantAssertionsSigned) {
        this.wantAssertionsSigned = wantAssertionsSigned;
    }

    public SamlExternalIdentityProvider getExternalSamlEntityByEntityId(String entityId) {
        for (SamlExternalEntity identityProvider : identityProviders) {
            SamlExternalIdentityProvider samlIdentityProvider = (SamlExternalIdentityProvider) identityProvider;
            if (samlIdentityProvider.getEntityId().equals(entityId)) {
                return samlIdentityProvider;
            }
        }
        return null;
    }

    public void writeMetaData(Writer writer) {
        try {
            ObjectFactory metaDataFactory = new ObjectFactory();

            IndexedEndpointType acsRedirectEndpoint = metaDataFactory.createIndexedEndpointType();
            acsRedirectEndpoint.setBinding(SamlConstants.HTTP_REDIRECT_BINDING);
            acsRedirectEndpoint.setLocation(getServiceURL(SamlServiceType.SAML_ASSERTION_CONSUMER_SERVICE));

            IndexedEndpointType acsPostEndpoint = metaDataFactory.createIndexedEndpointType();
            acsPostEndpoint.setBinding(SamlConstants.HTTP_POST_BINDING);
            acsPostEndpoint.setLocation(getServiceURL(SamlServiceType.SAML_ASSERTION_CONSUMER_SERVICE));

            SPSSODescriptorType spSsoDescriptor = metaDataFactory.createSPSSODescriptorType();

            spSsoDescriptor.getAssertionConsumerService().add(acsRedirectEndpoint);
            spSsoDescriptor.getAssertionConsumerService().add(acsPostEndpoint);
            addSloEndpointsToMetaData(spSsoDescriptor);

            spSsoDescriptor.setAuthnRequestsSigned(isAuthnRequestsSigned());
            spSsoDescriptor.setWantAssertionsSigned(isWantAssertionsSigned());

            spSsoDescriptor.getProtocolSupportEnumeration().add(SamlConstants.PROTOCOL_NSURI);

            addNameIDFormatsToMetaData(spSsoDescriptor);

            if (getSigningKey() != null) {
                addKeyDescriptorToMetaData(spSsoDescriptor);
            }

            EntityDescriptorType entityDescriptor = metaDataFactory.createEntityDescriptorType();
            entityDescriptor.setEntityID(getEntityId());
            entityDescriptor.getRoleDescriptorOrIDPSSODescriptorOrSPSSODescriptor().add(spSsoDescriptor);

            Marshaller marshaller = metaDataJaxbContext.createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_ENCODING, "UTF-8");
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
            marshaller.marshal(metaDataFactory.createEntityDescriptor(entityDescriptor), writer);
        } catch (JAXBException e) {
            throw new RuntimeException(e);
        }
    }

    @Dialogued(join = true)
    public void login(String idpEntityId, HttpServletResponse response) {
        SamlExternalIdentityProvider idp = getExternalSamlEntityByEntityId(idpEntityId);
        if (idp == null) {
            throw new RuntimeException("Identity provider " + idpEntityId + " not found");
        }

        samlSpSingleSignOnService.sendAuthenticationRequestToIDP(idp, response);
    }

    @Dialogued(join = true)
    public void localLogout(SamlSpSession session) {
        samlSpSessions.removeSession((SamlSpSessionImpl) session);
    }

    @Dialogued(join = true)
    public void globalLogout(SamlSpSession session, HttpServletResponse response) {
        localLogout(session);
        samlSpSingleLogoutService.sendSingleLogoutRequestToIDP((SamlSpSessionImpl) session, response);
    }

    public Set<SamlSpSession> getSessions() {
        Set<SamlSpSession> sessions = new HashSet<SamlSpSession>();
        sessions.addAll(samlSpSessions.getSessions());
        return sessions;
    }

    @Override
    public SamlIdpOrSp getIdpOrSp() {
        return SamlIdpOrSp.SP;
    }
}
