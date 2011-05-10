package org.jboss.seam.security.external.saml.idp;

import java.util.HashSet;
import java.util.Set;

import org.jboss.seam.security.external.saml.api.SamlIdpSession;
import org.jboss.seam.security.external.saml.api.SamlPrincipal;

/**
 * @author Marcel Kolsteren
 */
public class SamlIdpSessionImpl implements SamlIdpSession {
    private SamlPrincipal principal;

    private String sessionIndex;

    private Set<SamlExternalServiceProvider> serviceProviders = new HashSet<SamlExternalServiceProvider>();

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

    public Set<SamlExternalServiceProvider> getServiceProviders() {
        return serviceProviders;
    }

    public void setServiceProviders(Set<SamlExternalServiceProvider> serviceProviders) {
        this.serviceProviders = serviceProviders;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((principal == null) ? 0 : principal.hashCode());
        result = prime * result + ((sessionIndex == null) ? 0 : sessionIndex.hashCode());
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
        SamlIdpSessionImpl other = (SamlIdpSessionImpl) obj;
        if (principal == null) {
            if (other.principal != null)
                return false;
        } else if (!principal.equals(other.principal))
            return false;
        if (sessionIndex == null) {
            if (other.sessionIndex != null)
                return false;
        } else if (!sessionIndex.equals(other.sessionIndex))
            return false;
        return true;
    }

}
