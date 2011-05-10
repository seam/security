package org.jboss.seam.security.external.saml.sp;

import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.security.external.SamlMultiUserServiceProviderApi;
import org.jboss.seam.security.external.saml.api.SamlServiceProviderApi;
import org.jboss.seam.security.external.saml.api.SamlSpSession;

/**
 * @author Marcel Kolsteren
 */
public class SamlSpSingleUser implements SamlServiceProviderApi {
    @Inject
    private Instance<SamlMultiUserServiceProviderApi> multiUserApi;

    public void login(String idpEntityId, HttpServletResponse response) {
        multiUserApi.get().login(idpEntityId, response);
    }

    public void localLogout() {
        SamlSpSession session = getSession();
        if (session == null) {
            throw new IllegalStateException("Logout not possible because there is no current session.");
        }
        multiUserApi.get().localLogout(session);
    }

    public void globalLogout(HttpServletResponse response) {
        SamlSpSession session = getSession();
        if (session == null) {
            throw new IllegalStateException("Logout not possible because there is no current session.");
        }
        multiUserApi.get().globalLogout(session, response);
    }

    public SamlSpSession getSession() {
        if (multiUserApi.get().getSessions().size() == 0) {
            return null;
        } else {
            return multiUserApi.get().getSessions().iterator().next();
        }
    }
}
