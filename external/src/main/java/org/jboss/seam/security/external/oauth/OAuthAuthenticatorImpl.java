/*
 * JBoss, Home of Professional Open Source
 * Copyright 2012, Red Hat Middleware LLC, and individual contributors
 * by the @authors tag. See the copyright.txt in the distribution for a
 * full listing of individual contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jboss.seam.security.external.oauth;

import java.io.IOException;
import java.io.Serializable;
import java.lang.annotation.Annotation;
import java.util.Collection;
import java.util.List;

import javax.enterprise.context.SessionScoped;
import javax.enterprise.inject.Any;
import javax.enterprise.inject.Instance;
import javax.enterprise.inject.spi.BeanManager;
import javax.faces.context.FacesContext;
import javax.inject.Inject;
import javax.inject.Named;

import org.jboss.seam.security.AuthenticationException;
import org.jboss.seam.security.Authenticator;
import org.jboss.seam.security.BaseAuthenticator;
import org.jboss.seam.security.Identity;
import org.jboss.seam.security.events.DeferredAuthenticationEvent;
import org.jboss.seam.security.external.oauth.api.OAuthAuthenticator;
import org.jboss.seam.security.management.picketlink.IdentitySessionProducer;
import org.jboss.seam.social.MultiServicesManager;
import org.jboss.seam.social.SeamSocialExtension;
import org.jboss.seam.social.oauth.OAuthService;
import org.jboss.seam.social.oauth.OAuthSession;
import org.jboss.solder.core.Requires;
import org.jboss.solder.logging.Logger;
import org.picketlink.idm.api.Group;
import org.picketlink.idm.api.IdentitySession;
import org.picketlink.idm.api.Role;
import org.picketlink.idm.api.RoleType;
import org.picketlink.idm.api.User;
import org.picketlink.idm.common.exception.FeatureNotSupportedException;
import org.picketlink.idm.common.exception.IdentityException;

/**
 * An Authenticator implementation that uses OAuth to authenticate the user.
 * 
 * Based on OpenIdAuthenticator from Seam Security External module.
 * 
 * The OAuthAuthenticatorImpl has two modes of operation, depending on the value of the serviceName 1. Using the only configured
 * OAuthService if serviceName is null, this will raise an IllegalStateException if there is no or more than one available @ServiceRelated
 * OAuthService. 2. Using the multiServicesManager, in which case the serviceName selects the service which which to create a
 * new connection. This beans exists only if Seam Social is in the classpath
 * 
 * @author maschmid
 * @author Antoine Sabot-Durand
 * 
 */
@Requires("org.jboss.seam.social.oauth.OAuthService")
@Named("oauthAuthenticator")
@SessionScoped
public class OAuthAuthenticatorImpl extends BaseAuthenticator implements OAuthAuthenticator, Authenticator, Serializable {

    private static final long serialVersionUID = 3431696230531662201L;

    @Inject
    @Any
    private Instance<OAuthService> serviceInstances;

    private String serviceName = null;

    /**
     * If this property is set to true (the default) then user roles and attributes will be managed using the Identity
     * Management API.
     */
    private boolean identityManaged = true;

    @Inject
    Instance<Identity> identity;

    @Inject
    Instance<MultiServicesManager> multiServicesManager;

    @Inject
    Instance<IdentitySession> identitySession;

    @Inject
    Instance<IdentitySessionProducer> identitySessionProducer;

    @Inject
    Logger log;

    @Inject
    SeamSocialExtension extension;

    @Inject
    BeanManager beanManager;

    public boolean isIdentityManaged() {
        return identityManaged;
    }

    public void setIdentityManaged(boolean identityManaged) {
        this.identityManaged = identityManaged;
    }

    @Override
    public void setServiceName(String serviceName) {
        this.serviceName = serviceName;
    }

    @Override
    public String getServiceName() {
        return serviceName;
    }

    @Override
    public List<String> getListOfServices() {
        return multiServicesManager.get().getListOfServices();
    }

    private OAuthService getUnambiguousService() {
        // Attempts to get the only configured service
        if (extension.getSocialRelated().size() == 1) {
            String name = extension.getSocialRelated().iterator().next();
            Annotation qualifier = SeamSocialExtension.getServicesToQualifier().inverse().get(name);
            return serviceInstances.select(qualifier).get();
        } else {
            throw new IllegalStateException("Service name not set and there is no unambiguous OAuthService available");
        }
    }

    private OAuthService getCurrentService() {
        if (serviceName == null) {
            return getUnambiguousService();
        } else {
            return multiServicesManager.get().getCurrentService();
        }
    }

    @Override
    public void authenticate() {

        String authorizationUrl;

        if (serviceName == null) {
            log.debug("Service name null, authenticating with unamgiguous oauthService");
            OAuthService oauthService = getUnambiguousService();
            authorizationUrl = oauthService.getAuthorizationUrl();
        } else {
            log.debug("authenticating service \"" + serviceName + "\"");
            authorizationUrl = multiServicesManager.get().initNewSession(serviceName);
        }

        try {
            FacesContext.getCurrentInstance().getExternalContext().redirect(authorizationUrl);
            setStatus(AuthenticationStatus.DEFERRED);
        } catch (IOException e) {
            log.error("Failed to redirect ", e);
            setStatus(AuthenticationStatus.FAILURE);
        }
    }

    @Override
    public String getVerifierParamName() {
        return getCurrentService().getVerifierParamName();
    }

    @Override
    public String getVerifier() {
        return getCurrentService().getVerifier();
    }

    @Override
    public void setVerifier(String verifier) {
        getCurrentService().setVerifier(verifier);
    }

    @Override
    public void connect() {

        OAuthService currentService;
        OAuthSession currentSession;

        if (serviceName != null) {
            MultiServicesManager manager = multiServicesManager.get();
            manager.connectCurrentService();

            currentService = manager.getCurrentService();
            currentSession = manager.getCurrentSession();
        } else {
            currentService = getUnambiguousService();
            currentSession = currentService.getSession();

            currentService.initAccessToken();
        }

        OAuthUser user = new OAuthUser(currentService.getType(), currentSession.getUserProfile());

        if (isIdentityManaged()) {
            // By default we set the status to FAILURE, if we manage to get to the end
            // of this method we get rewarded with a SUCCESS
            setStatus(AuthenticationStatus.FAILURE);

            if (identitySessionProducer.get().isConfigured()) {
                validateManagedUser(user);
            }
        }

        setUser(user);
        setStatus(AuthenticationStatus.SUCCESS);

        beanManager.fireEvent(new DeferredAuthenticationEvent(true));
    }

    protected void validateManagedUser(OAuthUser principal) {
        IdentitySession session = identitySession.get();

        try {
            // Check that the user's identity exists
            if (session.getPersistenceManager().findUser(principal.getId()) == null) {
                // The user wasn't found, let's create them

                User user = session.getPersistenceManager().createUser(principal.getId());

                // TODO allow the OAuth -> IDM attribute mapping to be configured
                // e.g.
                // session.getAttributesManager().addAttribute(user, "fullName", principal.getUserProfile().getFullName());
                // session.getAttributesManager().addAttribute(user, "profileImageUrl",
                // principal.getUserProfile().getProfileImageUrl());

                // Load the user's roles and groups
                try {
                    Collection<RoleType> roleTypes = session.getRoleManager().findUserRoleTypes(user);

                    for (RoleType roleType : roleTypes) {
                        for (Role role : session.getRoleManager().findRoles(user, roleType)) {
                            identity.get().addRole(role.getRoleType().getName(), role.getGroup().getName(),
                                    role.getGroup().getGroupType());
                        }
                    }

                    for (Group g : session.getRelationshipManager().findAssociatedGroups(user)) {
                        identity.get().addGroup(g.getName(), g.getGroupType());
                    }
                } catch (FeatureNotSupportedException ex) {
                    throw new AuthenticationException("Error loading user's roles and groups", ex);
                } catch (IdentityException ex) {
                    throw new AuthenticationException("Error loading user's roles and groups", ex);
                }

            }
        } catch (IdentityException ex) {
            throw new AuthenticationException("Error locating User record for OAuth user", ex);
        }
    }
}
