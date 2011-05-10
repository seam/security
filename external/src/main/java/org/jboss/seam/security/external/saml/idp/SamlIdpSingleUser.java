package org.jboss.seam.security.external.saml.idp;

import java.util.List;

import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.security.external.SamlMultiUserIdentityProviderApi;
import org.jboss.seam.security.external.jaxb.samlv2.assertion.AttributeType;
import org.jboss.seam.security.external.saml.api.SamlIdentityProviderApi;
import org.jboss.seam.security.external.saml.api.SamlIdpSession;
import org.jboss.seam.security.external.saml.api.SamlNameId;

public class SamlIdpSingleUser implements SamlIdentityProviderApi {
    @Inject
    private Instance<SamlMultiUserIdentityProviderApi> multiUserApi;

    public void authenticationSucceeded(HttpServletResponse response) {
        multiUserApi.get().authenticationSucceeded(getSession(), response);
    }

    public void authenticationFailed(HttpServletResponse response) {
        multiUserApi.get().authenticationFailed(response);
    }

    public SamlIdpSession getSession() {
        if (multiUserApi.get().getSessions().size() == 0) {
            return null;
        } else {
            return multiUserApi.get().getSessions().iterator().next();
        }
    }

    public void localLogin(SamlNameId nameId, List<AttributeType> attributes) {
        multiUserApi.get().localLogin(nameId, attributes);
    }

    public void remoteLogin(String spEntityId, String remoteUrl, HttpServletResponse response) {
        SamlIdpSession session = getSession();
        if (session == null) {
            throw new IllegalStateException("Need to login locally first.");
        }
        multiUserApi.get().remoteLogin(spEntityId, session, remoteUrl, response);
    }

    public void localLogout() {
        SamlIdpSession session = getSession();
        if (session == null) {
            throw new IllegalStateException("Logout not possible because there is no current session.");
        }
        multiUserApi.get().localLogout(session);
    }

    public void globalLogout(HttpServletResponse response) {
        SamlIdpSession session = getSession();
        if (session == null) {
            throw new IllegalStateException("Logout not possible because there is no current session.");
        }
        multiUserApi.get().globalLogout(session, response);
    }

    public SamlNameId createNameId(String value, String format, String qualifier) {
        return multiUserApi.get().createNameId(value, format, qualifier);
    }
}
