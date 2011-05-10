package org.jboss.seam.security.external.saml.sp;

import org.jboss.seam.security.external.saml.api.SamlPrincipal;
import org.jboss.seam.security.external.saml.api.SamlSpSession;

/**
 * @author Marcel Kolsteren
 */
public class SamlSpSessionImpl implements SamlSpSession {
    private SamlPrincipal principal;

    private String sessionIndex;

    private SamlExternalIdentityProvider identityProvider;

    public SamlPrincipal getPrincipal() {
        return principal;
    }

    public void setPrincipal(SamlPrincipal samlPrincipal) {
        this.principal = samlPrincipal;
    }

    public String getSessionIndex() {
        return sessionIndex;
    }

    public void setSessionIndex(String sessionIndex) {
        this.sessionIndex = sessionIndex;
    }

    public SamlExternalIdentityProvider getIdentityProvider() {
        return identityProvider;
    }

    public void setIdentityProvider(SamlExternalIdentityProvider identityProvider) {
        this.identityProvider = identityProvider;
    }

}
