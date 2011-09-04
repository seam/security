package org.jboss.seam.security.external.openid;

import java.io.Serializable;
import java.util.LinkedList;
import java.util.List;

import javax.enterprise.context.SessionScoped;
import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import javax.inject.Named;
import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.logging.Logger;
import org.jboss.seam.security.Authenticator;
import org.jboss.seam.security.BaseAuthenticator;
import org.jboss.seam.security.Identity;
import org.jboss.seam.security.external.openid.api.OpenIdPrincipal;
import org.jboss.seam.security.external.openid.api.OpenIdRelyingPartyApi;
import org.jboss.seam.security.external.openid.api.OpenIdRequestedAttribute;
import org.jboss.seam.security.external.openid.providers.OpenIdProvider;
import org.picketlink.idm.api.IdentitySession;
import org.picketlink.idm.api.User;

/**
 * An Authenticator implementation that uses OpenID to authenticate the user.
 * 
 * @author Shane Bryzak
 */
public @Named("openIdAuthenticator")
@SessionScoped
class OpenIdAuthenticator extends BaseAuthenticator implements Authenticator, Serializable {
    private static final long serialVersionUID = 4669651866032932651L;

    @Inject
    Instance<OpenIdRelyingPartyApi> openIdApiInstance;

    @Inject
    List<OpenIdProvider> providers;

    @Inject
    Logger log;

    @Inject
    HttpServletResponse response;

    @Inject
    Instance<IdentitySession> identitySession;
    
    @Inject
    Identity identity;
    
    @Inject
    private Instance<OpenIdProviderRequest> openIdProviderRequest;

    /**
     * If this property is set to true (the default) then user roles and attributes will be managed using the Identity
     * Management API.
     */
    private boolean identityManaged = true;

    /**
     * This code indicates which OpenID provider should be used to authenticate against. See the classes in the
     * org.jboss.seam.security.external.openid.providers package.
     */
    private String providerCode;

    public boolean isIdentityManaged() {
        return identityManaged;
    }

    public void setIdentityManaged(boolean identityManaged) {
        this.identityManaged = identityManaged;
    }

    public String getProviderCode() {
        return providerCode;
    }

    public void setProviderCode(String providerCode) {
        this.providerCode = providerCode;
    }

    protected OpenIdProvider getSelectedProvider() {
        if (providerCode != null) {
            for (OpenIdProvider provider : providers) {
                if (providerCode.equals(provider.getCode()))
                    return provider;
            }
        }
        return null;
    }

    public void authenticate() {
        OpenIdProvider selectedProvider = getSelectedProvider();
        if (selectedProvider == null) {
            throw new IllegalStateException("No OpenID provider has been selected");
        }

        OpenIdRelyingPartyApi openIdApi = openIdApiInstance.get();

        List<OpenIdRequestedAttribute> attributes = new LinkedList<OpenIdRequestedAttribute>();

        selectedProvider.requestAttributes(openIdApi, attributes);

        openIdApi.login(selectedProvider.getUrl(), attributes, getResponse());

        setStatus(AuthenticationStatus.DEFERRED);
    }

    protected HttpServletResponse getResponse() {
        return response;
    }

    public List<OpenIdProvider> getProviders() {
        return providers;
    }

    public void success(OpenIdPrincipal principal) {
        User user = new OpenIdUser(principal);
        setUser(user);
        setStatus(AuthenticationStatus.SUCCESS);
        
        // FIXME this is a work in progress
        
        if (isIdentityManaged()) {
            // Ensure that the user's identity exists
            //IdentitySession session = identitySession.get();
            
            // Map fetched attributes to identity-managed attributes for new users 
            //openIdProviderRequest.get().getRequestedAttributes();
            
            // Load the user's roles
        }
    }
}
