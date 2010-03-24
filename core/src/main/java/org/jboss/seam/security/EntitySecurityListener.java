package org.jboss.seam.security;

import static org.jboss.seam.security.EntityAction.DELETE;
import static org.jboss.seam.security.EntityAction.INSERT;
import static org.jboss.seam.security.EntityAction.READ;
import static org.jboss.seam.security.EntityAction.UPDATE;

import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreRemove;
import javax.persistence.PreUpdate;


/**
 * Facilitates security checks for entity beans.
 * 
 * @author Shane Bryzak
 */
public class EntitySecurityListener
{
   /*
   @PostLoad
   public void postLoad(Object entity)
   {
      EntityPermissionChecker.instance().checkEntityPermission(entity, READ);
   }
   
   @PrePersist
   public void prePersist(Object entity)
   { 
      EntityPermissionChecker.instance().checkEntityPermission(entity, INSERT);
   }
   
   @PreUpdate
   public void preUpdate(Object entity)
   {
      EntityPermissionChecker.instance().checkEntityPermission(entity, UPDATE);
   }
   
   @PreRemove
   public void preRemove(Object entity)
   {
      EntityPermissionChecker.instance().checkEntityPermission(entity, DELETE);
   }
   */
}
