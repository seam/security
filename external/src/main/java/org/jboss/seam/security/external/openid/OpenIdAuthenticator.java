package org.jboss.seam.security.external.openid;

import java.io.Serializable;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

import javax.enterprise.context.SessionScoped;
import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import javax.inject.Named;
import javax.servlet.http.HttpServletResponse;

import org.jboss.solder.logging.Logger;
import org.jboss.seam.security.AuthenticationException;
import org.jboss.seam.security.Authenticator;
import org.jboss.seam.security.BaseAuthenticator;
import org.jboss.seam.security.Identity;
import org.jboss.seam.security.external.openid.api.OpenIdPrincipal;
import org.jboss.seam.security.external.openid.api.OpenIdRelyingPartyApi;
import org.jboss.seam.security.external.openid.api.OpenIdRequestedAttribute;
import org.jboss.seam.security.external.openid.providers.OpenIdProvider;
import org.jboss.seam.security.management.picketlink.IdentitySessionProducer;
import org.jboss.seam.transaction.Transactional;
import org.picketlink.idm.api.Group;
import org.picketlink.idm.api.IdentitySession;
import org.picketlink.idm.api.Role;
import org.picketlink.idm.api.RoleType;
import org.picketlink.idm.api.User;
import org.picketlink.idm.common.exception.FeatureNotSupportedException;
import org.picketlink.idm.common.exception.IdentityException;

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
    
    @Inject IdentitySessionProducer identitySessionProducer;
    
    @Inject
    Identity identity;

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
                        
        if (isIdentityManaged()) {
            // By default we set the status to FAILURE, if we manage to get to the end
            // of this method we get rewarded with a SUCCESS
            setStatus(AuthenticationStatus.FAILURE);        
         
            if (identitySessionProducer.isConfigured()) {
               validateManagedUser(principal);
            }
        }
        
        setUser(user);
        setStatus(AuthenticationStatus.SUCCESS);        
    }
    
    /**
     * Validates the OpenID user against the local Identity Management store. Important!! This method
     * must be invoked within an active transaction if you are using JpaIdentityStore (i.e., add the
     * @Transactional annotation to your authentication method). 
     * 
     * 
     * @param principal
     */
    protected void validateManagedUser(OpenIdPrincipal principal) {
        IdentitySession session = identitySession.get();
        
        try {            
            // Check that the user's identity exists
            if (session.getPersistenceManager().findUser(principal.getIdentifier()) == null) {
                // The user wasn't found, let's create them
                
                User user = session.getPersistenceManager().createUser(principal.getIdentifier());
                
                // TODO allow the OpenID -> IDM attribute mapping to be configured
                
                // Map fetched attributes to identity-managed attributes for new users 
                for (String alias : principal.getAttributeValues().keySet()) {
                    session.getAttributesManager().addAttribute(user, alias, principal.getAttribute(alias));    
                }               
                
                // Load the user's roles and groups        
                try {            
                    Collection<RoleType> roleTypes = session.getRoleManager().findUserRoleTypes(user);

                    for (RoleType roleType : roleTypes) {
                        for (Role role : session.getRoleManager().findRoles(user, roleType)) {
                            identity.addRole(role.getRoleType().getName(),
                                    role.getGroup().getName(), role.getGroup().getGroupType());
                        }
                    }
                    
                    for (Group g : session.getRelationshipManager().findAssociatedGroups(user)) {
                        identity.addGroup(g.getName(), g.getGroupType());
                    }
                } catch (FeatureNotSupportedException ex) {
                    throw new AuthenticationException("Error loading user's roles and groups", ex);
                } catch (IdentityException ex) {
                    throw new AuthenticationException("Error loading user's roles and groups", ex);
                }          
                
            }
        } catch (IdentityException ex) {
            throw new AuthenticationException("Error locating User record for OpenID user", ex);
        }     
    }
}
