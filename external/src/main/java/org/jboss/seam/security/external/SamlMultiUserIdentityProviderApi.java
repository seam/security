package org.jboss.seam.security.external;

import java.util.List;
import java.util.Set;

import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.security.external.jaxb.samlv2.assertion.AttributeType;
import org.jboss.seam.security.external.saml.api.SamlIdpSession;
import org.jboss.seam.security.external.saml.api.SamlNameId;

/**
 * @author Marcel Kolsteren
 */
public interface SamlMultiUserIdentityProviderApi {
    void authenticationSucceeded(SamlIdpSession session, HttpServletResponse response);

    void authenticationFailed(HttpServletResponse response);

    Set<SamlIdpSession> getSessions();

    SamlIdpSession localLogin(SamlNameId nameId, List<AttributeType> attributes);

    SamlNameId createNameId(String value, String format, String qualifier);

    void remoteLogin(String spEntityId, SamlIdpSession session, String remoteUrl, HttpServletResponse response);

    void localLogout(SamlIdpSession session);

    void globalLogout(SamlIdpSession session, HttpServletResponse response);
}
