package org.jboss.seam.security.external.openid;

import java.io.Serializable;
import java.util.LinkedList;
import java.util.List;

import javax.enterprise.context.SessionScoped;
import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import javax.inject.Named;
import javax.servlet.http.HttpServletResponse;

import org.jboss.logging.Logger;
import org.jboss.seam.security.Authenticator;
import org.jboss.seam.security.BaseAuthenticator;
import org.jboss.seam.security.external.openid.api.OpenIdPrincipal;
import org.jboss.seam.security.external.openid.api.OpenIdRelyingPartyApi;
import org.jboss.seam.security.external.openid.api.OpenIdRequestedAttribute;
import org.jboss.seam.security.external.openid.providers.OpenIdProvider;

/**
 * An Authenticator implementation that uses OpenID to authenticate the user.
 * 
 * @author Shane Bryzak
 */
public
@Named("openIdAuthenticator")
@SessionScoped
class OpenIdAuthenticator
        extends BaseAuthenticator implements Authenticator, Serializable {
    private static final long serialVersionUID = 4669651866032932651L;

    @Inject
    Instance<OpenIdRelyingPartyApi> openIdApiInstance;

    @Inject
    List<OpenIdProvider> providers;

    @Inject
    Logger log;
    
    @Inject HttpServletResponse response;
       
    private String providerCode;
    
    public String getProviderCode() {
        return providerCode;
    }

    public void setProviderCode(String providerCode) {
        this.providerCode = providerCode;
    }

    protected OpenIdProvider getSelectedProvider() {
        if (providerCode != null) {
            for (OpenIdProvider provider : providers) {
                if (providerCode.equals(provider.getCode())) return provider;
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
        setUser(new OpenIdUser(principal));
        setStatus(AuthenticationStatus.SUCCESS);
    }
}
