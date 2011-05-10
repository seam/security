package org.jboss.seam.security.external.contexts;

import javax.enterprise.context.spi.Contextual;
import javax.enterprise.context.spi.CreationalContext;

public class ContextualInstance<T> {
    private Contextual<T> contextual;

    private CreationalContext<T> creationalContext;

    private T instance;

    public ContextualInstance(Contextual<T> contextual, CreationalContext<T> creationalContext, T instance) {
        this.contextual = contextual;
        this.creationalContext = creationalContext;
        this.instance = instance;
    }

    public Contextual<T> getContextual() {
        return contextual;
    }

    public CreationalContext<T> getCreationalContext() {
        return creationalContext;
    }

    public T getInstance() {
        return instance;
    }

}
