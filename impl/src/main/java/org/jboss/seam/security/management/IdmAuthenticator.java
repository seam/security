package org.jboss.seam.security.management;

import java.util.Collection;

import javax.enterprise.inject.Model;
import javax.inject.Inject;

import org.jboss.solder.logging.Logger;
import org.jboss.seam.security.Authenticator;
import org.jboss.seam.security.BaseAuthenticator;
import org.jboss.seam.security.Credentials;
import org.jboss.seam.security.Identity;
import org.picketlink.idm.api.Credential;
import org.picketlink.idm.api.Group;
import org.picketlink.idm.api.IdentitySession;
import org.picketlink.idm.api.Role;
import org.picketlink.idm.api.RoleType;
import org.picketlink.idm.api.User;
import org.picketlink.idm.common.exception.FeatureNotSupportedException;
import org.picketlink.idm.common.exception.IdentityException;
import org.picketlink.idm.impl.api.model.SimpleUser;

/**
 * Authenticates using Identity Management
 *
 * @author Shane Bryzak
 */
public
@Model
class IdmAuthenticator extends BaseAuthenticator implements Authenticator {
    private static final Logger log = Logger.getLogger(IdmAuthenticator.class);

    @Inject
    IdentitySession identitySession;
    @Inject
    Credentials credentials;
    @Inject
    Identity identity;

    public void authenticate() {
        if (identitySession != null) {
            User u = new SimpleUser(credentials.getUsername());

            try {
                boolean success = identitySession.getAttributesManager().validateCredentials(
                        u, new Credential[]{credentials.getCredential()});

                if (success) {
                    Collection<RoleType> roleTypes = identitySession.getRoleManager()
                            .findUserRoleTypes(u);

                    for (RoleType roleType : roleTypes) {
                        for (Role role : identitySession.getRoleManager().findRoles(u, roleType)) {
                            identity.addRole(role.getRoleType().getName(),
                                    role.getGroup().getName(), role.getGroup().getGroupType());
                        }
                    }
                    
                    for (Group g : identitySession.getRelationshipManager().findAssociatedGroups(u)) {
                        identity.addGroup(g.getName(), g.getGroupType());
                    }
                    
                    setUser(u);
                    setStatus(AuthenticationStatus.SUCCESS);
                    return;
                } else {
                    log.info("Authentication failed for user '" + credentials.getUsername() + "'");
                }
            } catch (IdentityException ex) {
                log.error("Authentication error", ex);
            } catch (FeatureNotSupportedException ex) {
                log.error("Authentication error", ex);
            }
        }

        setStatus(AuthenticationStatus.FAILURE);
    }
}
