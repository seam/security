package org.jboss.seam.security.permission;

import java.io.Serializable;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.inject.Inject;
import javax.enterprise.inject.spi.BeanManager;

import org.jboss.seam.beans.BeanManagerHelper;
import org.jboss.seam.security.Identity;
import org.jboss.seam.security.Role;
import org.jboss.seam.security.SimplePrincipal;
import org.jboss.webbeans.log.Log;
import org.jboss.webbeans.log.Logger;

/**
 * Resolves dynamically-assigned permissions, mapped to a user or a role, and kept in persistent
 * storage, such as a relational database.
 * 
 * @author Shane Bryzak
 */
public class PersistentPermissionResolver implements PermissionResolver, Serializable
{
   private static final long serialVersionUID = -603389172032219059L;

   private PermissionStore permissionStore;
   
   @Logger Log log;
   
   @Inject BeanManager manager;
   @Inject Identity identity;
   @Inject RuleBasedPermissionResolver ruleBasedPermissionResolver;

   @Inject
   public void initPermissionStore()
   {
      if (permissionStore == null)
      {
         permissionStore = BeanManagerHelper.getInstanceByType(manager, JpaPermissionStore.class);
      }
      
      if (permissionStore == null)
      {
         log.warn("no permission store available - please install a PermissionStore if persistent permissions are required.");
      }
   }
   
   public PermissionStore getPermissionStore()
   {
      return permissionStore;
   }
   
   public void setPermissionStore(PermissionStore permissionStore)
   {
      this.permissionStore = permissionStore;
   }
   
   public boolean hasPermission(Object target, String action)
   {
      if (permissionStore == null) return false;
            
      if (!identity.isLoggedIn()) return false;
      
      List<Permission> permissions = permissionStore.listPermissions(target, action);
      
      String username = identity.getPrincipal().getName();
      
      for (Permission permission : permissions)
      {
         if (permission.getRecipient() instanceof SimplePrincipal &&
               username.equals(permission.getRecipient().getName()))
         {
            return true;
         }
         
         if (permission.getRecipient() instanceof Role)
         {
            Role role = (Role) permission.getRecipient();
            
            if (role.isConditional())
            {
               if (ruleBasedPermissionResolver.checkConditionalRole(role.getName(), target, action)) return true;
            }
            else if (identity.hasRole(role.getName()))
            {
               return true;
            }
         }
      }
      
      return false;
   }
   
   public void filterSetByAction(Set<Object> targets, String action)
   {
      if (permissionStore == null) return;
      
      if (!identity.isLoggedIn()) return;
      
      List<Permission> permissions = permissionStore.listPermissions(targets, action);
      
      String username = identity.getPrincipal().getName();
      
      Iterator iter = targets.iterator();
      while (iter.hasNext())
      {
         Object target = iter.next();
         
         for (Permission permission : permissions)
         {
            if (permission.getTarget().equals(target))
            {
               if (permission.getRecipient() instanceof SimplePrincipal &&
                     username.equals(permission.getRecipient().getName()))
               {
                  iter.remove();
                  break;
               }
               
               if (permission.getRecipient() instanceof Role)
               {
                  Role role = (Role) permission.getRecipient();
                  
                  if (role.isConditional())
                  {
                     if (ruleBasedPermissionResolver.checkConditionalRole(role.getName(), target, action))
                     {
                        iter.remove();
                        break;
                     }
                  }
                  else if (identity.hasRole(role.getName()))
                  {
                     iter.remove();
                     break;
                  }
               }
            }
         }
      }
   }
}
