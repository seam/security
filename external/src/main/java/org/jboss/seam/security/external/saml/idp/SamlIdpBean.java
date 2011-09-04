package org.jboss.seam.security.external.saml.idp;

import java.io.Reader;
import java.io.Writer;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import javax.enterprise.inject.Instance;
import javax.enterprise.inject.Typed;
import javax.inject.Inject;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import org.jboss.seam.security.external.SamlNameIdImpl;
import org.jboss.seam.security.external.SamlPrincipalImpl;
import org.jboss.seam.security.external.dialogues.api.Dialogued;
import org.jboss.seam.security.external.jaxb.samlv2.assertion.AttributeType;
import org.jboss.seam.security.external.jaxb.samlv2.metadata.EntityDescriptorType;
import org.jboss.seam.security.external.jaxb.samlv2.metadata.IDPSSODescriptorType;
import org.jboss.seam.security.external.jaxb.samlv2.metadata.IndexedEndpointType;
import org.jboss.seam.security.external.jaxb.samlv2.metadata.ObjectFactory;
import org.jboss.seam.security.external.jaxb.samlv2.metadata.SPSSODescriptorType;
import org.jboss.seam.security.external.saml.SamlConstants;
import org.jboss.seam.security.external.saml.SamlDialogue;
import org.jboss.seam.security.external.saml.SamlEntityBean;
import org.jboss.seam.security.external.saml.SamlExternalEntity;
import org.jboss.seam.security.external.saml.SamlIdpOrSp;
import org.jboss.seam.security.external.saml.SamlServiceType;
import org.jboss.seam.security.external.saml.api.SamlIdpSession;
import org.jboss.seam.security.external.saml.api.SamlNameId;
import org.jboss.seam.security.external.saml.api.SamlPrincipal;

/**
 * @author Marcel Kolsteren
 */
@Typed(SamlIdpBean.class)
public class SamlIdpBean extends SamlEntityBean implements SamlIdpBeanApi {
    @Inject
    private SamlIdpSingleSignOnService samlIdpSingleSignOnService;

    @Inject
    private SamlIdpSingleLogoutService samlIdpSingleSignLogoutService;

    @Inject
    private SamlIdpSessions samlIdpSessions;

    private List<SamlExternalServiceProvider> serviceProviders = new LinkedList<SamlExternalServiceProvider>();

    // No boolean assertionsSigned: the identity provider always signs the
    // assertions.

    private boolean wantAuthnRequestsSigned = false;

    @Inject
    private Instance<SamlDialogue> samlDialogue;

    public List<SamlExternalServiceProvider> getServiceProviders() {
        return serviceProviders;
    }

    public SamlExternalServiceProvider addExternalServiceProvider(String entityId, SPSSODescriptorType spSsoDescriptor) {
        SamlExternalServiceProvider samlServiceProvider = new SamlExternalServiceProvider(entityId, spSsoDescriptor);
        serviceProviders.add(samlServiceProvider);
        return samlServiceProvider;
    }

    public SamlExternalServiceProvider addExternalSamlEntity(Reader reader) {
        EntityDescriptorType entityDescriptor = readEntityDescriptor(reader);
        String entityId = entityDescriptor.getEntityID();
        SPSSODescriptorType SPSSODescriptor = (SPSSODescriptorType) entityDescriptor.getRoleDescriptorOrIDPSSODescriptorOrSPSSODescriptor().get(0);
        return addExternalServiceProvider(entityId, SPSSODescriptor);
    }

    @Override
    public List<SamlExternalEntity> getExternalSamlEntities() {
        List<SamlExternalEntity> samlEntities = new LinkedList<SamlExternalEntity>();
        for (SamlExternalServiceProvider sp : serviceProviders) {
            samlEntities.add(sp);
        }
        return samlEntities;
    }

    public boolean isWantAuthnRequestsSigned() {
        return wantAuthnRequestsSigned;
    }

    public void setWantAuthnRequestsSigned(boolean wantAuthnRequestsSigned) {
        this.wantAuthnRequestsSigned = wantAuthnRequestsSigned;
    }

    public SamlExternalServiceProvider getExternalSamlEntityByEntityId(String entityId) {
        for (SamlExternalServiceProvider serviceProvider : serviceProviders) {
            if (serviceProvider.getEntityId().equals(entityId)) {
                return serviceProvider;
            }
        }
        return null;
    }

    public void writeMetaData(Writer writer) {
        try {
            ObjectFactory metaDataFactory = new ObjectFactory();

            IndexedEndpointType ssoRedirectEndpoint = metaDataFactory.createIndexedEndpointType();
            ssoRedirectEndpoint.setBinding(SamlConstants.HTTP_REDIRECT_BINDING);
            ssoRedirectEndpoint.setLocation(getServiceURL(SamlServiceType.SAML_SINGLE_SIGN_ON_SERVICE));

            IndexedEndpointType ssoPostEndpoint = metaDataFactory.createIndexedEndpointType();
            ssoPostEndpoint.setBinding(SamlConstants.HTTP_POST_BINDING);
            ssoPostEndpoint.setLocation(getServiceURL(SamlServiceType.SAML_SINGLE_SIGN_ON_SERVICE));

            IDPSSODescriptorType idpSsoDescriptor = metaDataFactory.createIDPSSODescriptorType();

            idpSsoDescriptor.getSingleSignOnService().add(ssoRedirectEndpoint);
            idpSsoDescriptor.getSingleSignOnService().add(ssoPostEndpoint);
            addSloEndpointsToMetaData(idpSsoDescriptor);

            idpSsoDescriptor.setWantAuthnRequestsSigned(isWantAuthnRequestsSigned());

            idpSsoDescriptor.getProtocolSupportEnumeration().add(SamlConstants.PROTOCOL_NSURI);

            addNameIDFormatsToMetaData(idpSsoDescriptor);

            addKeyDescriptorToMetaData(idpSsoDescriptor);

            EntityDescriptorType entityDescriptor = metaDataFactory.createEntityDescriptorType();
            entityDescriptor.setEntityID(getEntityId());
            entityDescriptor.getRoleDescriptorOrIDPSSODescriptorOrSPSSODescriptor().add(idpSsoDescriptor);

            Marshaller marshaller = metaDataJaxbContext.createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_ENCODING, "UTF-8");
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
            marshaller.marshal(metaDataFactory.createEntityDescriptor(entityDescriptor), writer);
        } catch (JAXBException e) {
            throw new RuntimeException(e);
        }
    }

    @Dialogued(join = true)
    public void authenticationSucceeded(SamlIdpSession session, HttpServletResponse response) {
        session.getServiceProviders().add((SamlExternalServiceProvider) samlDialogue.get().getExternalProvider());
        samlIdpSingleSignOnService.handleSucceededAuthentication(session, response);
    }

    @Dialogued(join = true)
    public void authenticationFailed(HttpServletResponse response) {
        samlIdpSingleSignOnService.handleFailedAuthentication(response);
    }

    public Set<SamlIdpSession> getSessions() {
        Set<SamlIdpSession> sessions = new HashSet<SamlIdpSession>();
        sessions.addAll(samlIdpSessions.getSessions());
        return sessions;
    }

    public SamlIdpSession localLogin(SamlNameId nameId, List<AttributeType> attributes) {
        return createSession(nameId, attributes);
    }

    public SamlNameId createNameId(String value, String format, String qualifier) {
        return new SamlNameIdImpl(value, format, qualifier);
    }

    private SamlIdpSession createSession(SamlNameId nameId, List<AttributeType> attributes) {
        SamlPrincipalImpl samlPrincipal = new SamlPrincipalImpl();
        samlPrincipal.setNameId(nameId);
        if (attributes != null) {
            samlPrincipal.setAttributes(attributes);
        } else {
            samlPrincipal.setAttributes(new LinkedList<AttributeType>());
        }
        return samlIdpSessions.addSession(samlPrincipal);
    }

    @Dialogued(join = true)
    public void remoteLogin(String spEntityId, SamlIdpSession session, String remoteUrl, HttpServletResponse response) {
        for (SamlExternalServiceProvider sp : session.getServiceProviders()) {
            if (sp.getEntityId().equals(spEntityId)) {
                throw new RuntimeException("Service provider " + spEntityId + " is already a session participant.");
            }
        }
        session.getServiceProviders().add(getExternalSamlEntityByEntityId(spEntityId));
        samlIdpSingleSignOnService.remoteLogin(spEntityId, session, remoteUrl, response);
    }

    public void localLogout(SamlIdpSession session) {
        samlIdpSessions.removeSession((SamlIdpSessionImpl) session);
    }

    @Dialogued(join = true)
    public void globalLogout(SamlIdpSession session, HttpServletResponse response) {
        SamlPrincipal principal = session.getPrincipal();
        samlIdpSingleSignLogoutService.handleIDPInitiatedSingleLogout(principal, Arrays.asList(((SamlIdpSessionImpl) session).getSessionIndex()), response);
    }

    @Override
    public SamlIdpOrSp getIdpOrSp() {
        return SamlIdpOrSp.IDP;
    }
}
