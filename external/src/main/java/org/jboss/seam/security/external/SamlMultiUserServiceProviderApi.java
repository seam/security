package org.jboss.seam.security.external;

import java.util.Set;

import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.security.external.saml.api.SamlSpSession;

/**
 * @author Marcel Kolsteren
 */
public interface SamlMultiUserServiceProviderApi {
    public void login(String idpEntityId, HttpServletResponse response);

    public void localLogout(SamlSpSession session);

    public void globalLogout(SamlSpSession session, HttpServletResponse response);

    public Set<SamlSpSession> getSessions();
}
