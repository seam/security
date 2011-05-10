package org.jboss.seam.security;

import javax.enterprise.context.ApplicationScoped;

/**
 * Entity permission checks
 *
 * @author Shane Bryzak
 */
@ApplicationScoped
public class EntityPermissionChecker {
    /*
    private String entityManagerName = "entityManager";

    @Current Manager manager;

    private EntityManager getEntityManager()
    {
       return (EntityManager) Component.getInstance(entityManagerName);
    }

    public String getEntityManagerName()
    {
       return entityManagerName;
    }

    public void setEntityManagerName(String name)
    {
       this.entityManagerName = name;
    }

    public void checkEntityPermission(Object entity, EntityAction action)
    {
       if (!Identity.isSecurityEnabled()) return;

       Identity identity = manager.getInstanceByType(Identity.class);
       identity.tryLogin();

       PersistenceProvider provider = manager.getInstanceByType(PersistenceProvider.class);

       Class beanClass = provider.getBeanClass(entity);

       if (beanClass != null)
       {
          Method m = null;
          switch (action)
          {
             case READ:
                m = provider.getPostLoadMethod(entity, getEntityManager());
                break;
             case INSERT:
                m = provider.getPrePersistMethod(entity, getEntityManager());
                break;
             case UPDATE:
                m = provider.getPreUpdateMethod(entity, getEntityManager());
                break;
             case DELETE:
                m = provider.getPreRemoveMethod(entity, getEntityManager());
          }

          Restrict restrict = null;

          if (m != null && m.isAnnotationPresent(Restrict.class))
          {
             restrict = m.getAnnotation(Restrict.class);
          }
          else if (entity.getClass().isAnnotationPresent(Restrict.class))
          {
             restrict = entity.getClass().getAnnotation(Restrict.class);
          }

          if (restrict != null)
          {
             if (Strings.isEmpty(restrict.value()))
             {
                identity.checkPermission(entity, action.toString());
             }
             else
             {
                identity.checkRestriction(restrict.value());
             }
          }
       }
    }
    */
}
