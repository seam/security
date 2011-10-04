package org.jboss.seam.security;

import java.lang.annotation.Annotation;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;
import javax.inject.Inject;

import org.jboss.seam.security.AuthorizationException;
import org.jboss.seam.security.events.AuthorizationCheckEvent;

/**
 * This event observer
 *
 * @author Shane Bryzak
 */
public
@ApplicationScoped
class AuthorizationObserver {
    @Inject
    SecurityExtension extension;

    public void observeAuthorizationCheckEvent(@Observes AuthorizationCheckEvent event) {
        boolean failed = false;

        for (Annotation binding : event.getBindings()) {
            try {
                extension.checkAuthorization(binding);
            } catch (AuthorizationException ex) {
                failed = true;
            }
        }

        if (!failed) {
            event.setPassed(true);
        }
    }
}
