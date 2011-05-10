package org.jboss.seam.security.external.virtualapplications;

import java.lang.annotation.Annotation;

import javax.enterprise.context.ContextNotActiveException;
import javax.enterprise.context.spi.Context;
import javax.enterprise.context.spi.Contextual;
import javax.enterprise.context.spi.CreationalContext;
import javax.servlet.ServletContext;

import org.jboss.seam.security.external.contexts.ContextualInstance;
import org.jboss.seam.security.external.contexts.HashMapBeanStore;
import org.jboss.seam.security.external.virtualapplications.api.VirtualApplicationScoped;

/**
 * @author Marcel Kolsteren
 */
public class VirtualApplicationContext implements Context {
    private static final String BEAN_STORE_ATTRIBUTE_NAME_PREFIX = "virtualApplicationContextBeanStore";

    private ServletContext servletContext;

    private final ThreadLocal<String> hostNameThreadLocal;

    public VirtualApplicationContext() {
        hostNameThreadLocal = new ThreadLocal<String>();
    }

    protected HashMapBeanStore getBeanStore() {
        return getBeanStore(hostNameThreadLocal.get());
    }

    private HashMapBeanStore getBeanStore(String hostName) {
        HashMapBeanStore beanStore = (HashMapBeanStore) servletContext.getAttribute(getAttributeName(hostName));
        return beanStore;
    }

    private void createBeanStore(String hostName) {
        HashMapBeanStore beanStore = new HashMapBeanStore();
        servletContext.setAttribute(getAttributeName(hostName), beanStore);
    }

    private void removeBeanStore(String hostName) {
        servletContext.removeAttribute(getAttributeName(hostName));
    }

    private String getAttributeName(String hostName) {
        return BEAN_STORE_ATTRIBUTE_NAME_PREFIX + "_" + hostName;
    }

    public void initialize(ServletContext servletContext) {
        this.servletContext = servletContext;
    }

    public void destroy() {
        this.servletContext = null;
    }

    public void create(String hostName) {
        createBeanStore(hostName);
        attach(hostName);
    }

    public void remove() {
        getBeanStore().clear();
        removeBeanStore(this.hostNameThreadLocal.get());
        detach();
    }

    public boolean isExistingVirtualApplication(String hostName) {
        return servletContext != null && getBeanStore(hostName) != null;
    }

    public void attach(String hostName) {
        this.hostNameThreadLocal.set(hostName);
    }

    public void detach() {
        this.hostNameThreadLocal.set(null);
    }

    public <T> T get(Contextual<T> contextual, CreationalContext<T> creationalContext) {
        if (!isActive()) {
            throw new ContextNotActiveException();
        }
        ContextualInstance<T> beanInstance = getBeanStore().get(contextual);
        if (beanInstance != null) {
            return beanInstance.getInstance();
        } else if (creationalContext != null) {
            T instance = contextual.create(creationalContext);
            if (instance != null) {
                beanInstance = new ContextualInstance<T>(contextual, creationalContext, instance);
                getBeanStore().put(contextual, beanInstance);
            }
            return instance;
        } else {
            return null;
        }
    }

    public <T> T get(Contextual<T> contextual) {
        return get(contextual, null);
    }

    public Class<? extends Annotation> getScope() {
        return VirtualApplicationScoped.class;
    }

    public boolean isActive() {
        return hostNameThreadLocal.get() != null;
    }
}
