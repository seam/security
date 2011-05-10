package org.jboss.seam.security.permission;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.enterprise.inject.Instance;
import javax.enterprise.inject.spi.BeanManager;
import javax.inject.Inject;
import javax.persistence.Entity;
import javax.persistence.EntityManager;

import org.jboss.seam.security.annotations.permission.Identifier;
import org.jboss.seam.security.util.Strings;

/**
 * An Identifier strategy for entity-based permission checks
 *
 * @author Shane Bryzak
 */
public class EntityIdentifierStrategy implements IdentifierStrategy {
    private Map<Class<?>, String> identifierNames = new ConcurrentHashMap<Class<?>, String>();

    //@Inject PersistenceProvider persistenceProvider;
    //@Inject Expressions expressions;

    @Inject
    BeanManager manager;
    @Inject
    Instance<EntityManager> entityManagerInstance;

    public boolean canIdentify(Class<?> targetClass) {
        return targetClass.isAnnotationPresent(Entity.class);
    }

    public String getIdentifier(Object target) {
        return String.format("%s:%s", getIdentifierName(target.getClass()),
                // FIXME
                null);
        //persistenceProvider.getId(target, lookupEntityManager()).toString());
    }

    private String getIdentifierName(Class<?> cls) {
        if (!identifierNames.containsKey(cls)) {
            String name = null;

            if (cls.isAnnotationPresent(Identifier.class)) {
                Identifier identifier = (Identifier) cls.getAnnotation(Identifier.class);
                if (!Strings.isEmpty(identifier.name())) {
                    name = identifier.name();
                }
            }

            if (name == null) {
                name = cls.getName().substring(cls.getName().lastIndexOf('.') + 1);
            }

            identifierNames.put(cls, name);
            return name;
        }

        return identifierNames.get(cls);
    }
}
