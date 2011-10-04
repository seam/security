package org.jboss.seam.security.external.contexts;

import java.util.HashMap;
import java.util.Map;

import javax.enterprise.context.spi.Contextual;

/**
 * Non-serializable bean store, based on a hash map. This bean store should not
 * be used for passivating scopes!
 *
 * @author Marcel Kolsteren
 */
public class HashMapBeanStore {

    protected Map<Contextual<?>, ContextualInstance<? extends Object>> contextualInstanceMap;

    public HashMapBeanStore() {
        contextualInstanceMap = new HashMap<Contextual<?>, ContextualInstance<? extends Object>>();
    }

    public <T extends Object> ContextualInstance<T> get(Contextual<T> contextual) {
        @SuppressWarnings("unchecked")
        ContextualInstance<T> instance = (ContextualInstance<T>) contextualInstanceMap.get(contextual);
        return instance;
    }

    private <T> void destroy(Contextual<T> contextual) {
        ContextualInstance<T> beanInstance = get(contextual);
        beanInstance.getContextual().destroy(beanInstance.getInstance(), beanInstance.getCreationalContext());
    }

    public void clear() {
        for (Contextual<?> contextual : contextualInstanceMap.keySet()) {
            destroy(contextual);
        }
        contextualInstanceMap.clear();
    }

    public <T> void put(Contextual<T> contextual, ContextualInstance<T> beanInstance) {
        contextualInstanceMap.put(contextual, beanInstance);
    }
}
