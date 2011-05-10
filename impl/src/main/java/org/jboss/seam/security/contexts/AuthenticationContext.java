package org.jboss.seam.security.contexts;

import java.lang.annotation.Annotation;

import javax.enterprise.context.spi.Context;
import javax.enterprise.context.spi.Contextual;
import javax.enterprise.context.spi.CreationalContext;

import org.jboss.seam.security.AuthenticationScoped;

/**
 * @author Shane Bryzak
 */
public class AuthenticationContext implements Context {
    private boolean active;

    public Class<? extends Annotation> getScope() {
        return AuthenticationScoped.class;
    }

    public <T> T get(Contextual<T> contextual,
                     CreationalContext<T> creationalContext) {
        // FIXME
        return null;

    }

    public <T> T get(Contextual<T> contextual) {
        return get(contextual, null);
    }

    public boolean isActive() {
        return active;
    }

}
