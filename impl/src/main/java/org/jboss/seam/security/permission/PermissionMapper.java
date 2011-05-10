package org.jboss.seam.security.permission;

import java.io.Serializable;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Instance;
import javax.enterprise.inject.spi.BeanManager;
import javax.inject.Inject;

/**
 * Maps permission checks to resolver chains
 *
 * @author Shane Bryzak
 */
@ApplicationScoped
public class PermissionMapper implements Serializable {
    private static final long serialVersionUID = 7692687882996064772L;

    @Inject
    Instance<PermissionResolver> resolvers;
    @Inject
    BeanManager manager;

    public boolean resolvePermission(Object resource, String permission) {
        for (PermissionResolver resolver : resolvers) {
            if (resolver.hasPermission(resource, permission)) return true;
        }
        return false;
    }

    public void filterByPermission(Collection<?> collection, String action) {
        boolean homogenous = true;

        Class<?> targetClass = null;
        for (Object target : collection) {
            if (targetClass == null) targetClass = target.getClass();
            if (!targetClass.equals(target.getClass())) {
                homogenous = false;
                break;
            }
        }

        if (homogenous) {
            Set<Object> denied = new HashSet<Object>(collection);

            for (PermissionResolver resolver : resolvers) {
                resolver.filterSetByAction(denied, action);
            }

            for (Object target : denied) {
                collection.remove(target);
            }
        } else {
            Map<Class<?>, Set<Object>> deniedByClass = new HashMap<Class<?>, Set<Object>>();
            for (Object obj : collection) {
                if (!deniedByClass.containsKey(obj.getClass())) {
                    Set<Object> denied = new HashSet<Object>();
                    denied.add(obj);
                    deniedByClass.put(obj.getClass(), denied);
                } else {
                    deniedByClass.get(obj.getClass()).add(obj);
                }
            }

            for (Class<?> cls : deniedByClass.keySet()) {
                Set<Object> denied = deniedByClass.get(cls);
                for (PermissionResolver resolver : resolvers) {
                    resolver.filterSetByAction(denied, action);
                }

                for (Object target : denied) {
                    collection.remove(target);
                }
            }
        }
    }
}
