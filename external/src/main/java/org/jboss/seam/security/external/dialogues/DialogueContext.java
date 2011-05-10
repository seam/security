package org.jboss.seam.security.external.dialogues;

import java.lang.annotation.Annotation;
import java.util.UUID;

import javax.enterprise.context.ContextNotActiveException;
import javax.enterprise.context.spi.Context;
import javax.enterprise.context.spi.Contextual;
import javax.enterprise.context.spi.CreationalContext;
import javax.servlet.ServletContext;

import org.jboss.seam.security.external.contexts.ContextualInstance;
import org.jboss.seam.security.external.contexts.HashMapBeanStore;
import org.jboss.seam.security.external.dialogues.api.DialogueScoped;

/**
 * @author Marcel Kolsteren
 */
public class DialogueContext implements Context {
    private static final String BEAN_STORE_ATTRIBUTE_NAME_PREFIX = "DialogueContextBeanStore";

    private ServletContext servletContext;

    private final ThreadLocal<String> dialogueIdThreadLocal;

    public DialogueContext() {
        dialogueIdThreadLocal = new ThreadLocal<String>();
    }

    protected HashMapBeanStore getBeanStore() {
        return getBeanStore(dialogueIdThreadLocal.get());
    }

    private HashMapBeanStore getBeanStore(String dialogueId) {
        HashMapBeanStore beanStore = (HashMapBeanStore) servletContext.getAttribute(getAttributeName(dialogueId));
        return beanStore;
    }

    private void createBeanStore(String dialogueId) {
        HashMapBeanStore beanStore = new HashMapBeanStore();
        servletContext.setAttribute(getAttributeName(dialogueId), beanStore);
    }

    private void removeBeanStore(String dialogueId) {
        servletContext.removeAttribute(getAttributeName(dialogueId));
    }

    private String getAttributeName(String dialogueId) {
        return BEAN_STORE_ATTRIBUTE_NAME_PREFIX + "_" + dialogueId;
    }

    public void initialize(ServletContext servletContext) {
        this.servletContext = servletContext;
    }

    public void destroy() {
        this.servletContext = null;
    }

    public String create() {
        if (this.dialogueIdThreadLocal.get() != null) {
            throw new RuntimeException("Already attached to a dialogue");
        }

        String dialogueId;
        do {
            dialogueId = UUID.randomUUID().toString();
        }
        while (getBeanStore(dialogueId) != null);

        this.dialogueIdThreadLocal.set(dialogueId);
        createBeanStore(dialogueId);
        return dialogueId;
    }

    public void remove() {
        getBeanStore().clear();
        removeBeanStore(this.dialogueIdThreadLocal.get());
        this.dialogueIdThreadLocal.set(null);
    }

    public boolean isExistingDialogue(String dialogueId) {
        return getBeanStore(dialogueId) != null;
    }

    /**
     * Attaches an existing dialogue to the current thread
     *
     * @param dialogueIdThreadLocal
     */
    public void attach(String dialogueId) {
        if (this.dialogueIdThreadLocal.get() != null) {
            throw new RuntimeException("Already attached to a dialogue");
        }
        if (!isExistingDialogue(dialogueId)) {
            throw new RuntimeException("There is no active context with request id " + dialogueId);
        }
        this.dialogueIdThreadLocal.set(dialogueId);
    }

    /**
     * Detaches the dialogue from the current thread
     */
    public void detach() {
        this.dialogueIdThreadLocal.set(null);
    }

    public boolean isAttached() {
        return dialogueIdThreadLocal.get() != null;
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
        return DialogueScoped.class;
    }

    public boolean isActive() {
        return dialogueIdThreadLocal.get() != null;
    }
}
