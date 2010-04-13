package org.jboss.seam.security.permission;

import java.io.Serializable;
import java.security.Principal;
import java.security.acl.Group;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.enterprise.context.SessionScoped;
import javax.inject.Inject;
import javax.enterprise.inject.spi.BeanManager;
import javax.enterprise.event.Observes;

import org.drools.KnowledgeBase;
import org.drools.RuleBase;
import org.drools.StatefulSession;
import org.drools.ClassObjectFilter;
import org.drools.runtime.StatefulKnowledgeSession;
import org.drools.runtime.rule.FactHandle;
//import org.jboss.seam.drools.SeamGlobalResolver;
import org.jboss.seam.security.Identity;
import org.jboss.seam.security.IdentityImpl;
import org.jboss.seam.security.Role;
import org.jboss.seam.security.events.LoggedOutEvent;
import org.jboss.seam.security.events.PostAuthenticateEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A permission resolver that uses a Drools rule base to perform permission checks
 * 
 * @author Shane Bryzak
 */
@SessionScoped
public class RuleBasedPermissionResolver implements PermissionResolver, Serializable
{
   private static final long serialVersionUID = -7572627522601793024L;

   private Logger log = LoggerFactory.getLogger(RuleBasedPermissionResolver.class);
   
   private StatefulKnowledgeSession securityContext;
   
   private KnowledgeBase securityRules;
   
   @Inject BeanManager manager;
   @Inject Identity identity;
   
   @Inject
   public boolean create()
   {
      initSecurityContext();
      return getSecurityContext() != null;
   }
   
   protected void initSecurityContext()
   {
      if (getSecurityRules() != null)
      {
         setSecurityContext(getSecurityRules().newStatefulKnowledgeSession());
         //getSecurityContext().setGlobalResolver(new SeamGlobalResolver(getSecurityContext().getGlobalResolver()));
      }
   }
   
   /**
    * Performs a permission check for the specified name and action
    * 
    * @param target Object The target of the permission check
    * @param action String The action to be performed on the target
    * @return boolean True if the user has the specified permission
    */
   public boolean hasPermission(Object target, String action)
   {
      StatefulKnowledgeSession securityContext = getSecurityContext();
      
      if (securityContext == null) return false;
      
      List<FactHandle> handles = new ArrayList<FactHandle>();

      PermissionCheck check;
      
      synchronized( securityContext )
      {
         if (!(target instanceof String) && !(target instanceof Class))
         {
            handles.add( securityContext.insert(target) );
         }
         else if (target instanceof Class)
         {
            // TODO fix
            String componentName = null; // manager. Seam.getComponentName((Class) target);
            target = componentName != null ? componentName : ((Class) target).getName();
         }
         
         check = new PermissionCheck(target, action);
         
         try
         {
            synchronizeContext();
            
            handles.add( securityContext.insert(check) );
   
            securityContext.fireAllRules();
         }
         finally
         {
            for (FactHandle handle : handles)
            {
               securityContext.retract(handle);
            }
         }
      }
      
      return check.isGranted();
   }
   
   public void filterSetByAction(Set<Object> targets, String action)
   {
      Iterator iter = targets.iterator();
      while (iter.hasNext())
      {
         Object target = iter.next();
         if (hasPermission(target, action)) iter.remove();
      }
   }
   
   public boolean checkConditionalRole(String roleName, Object target, String action)
   {
      StatefulKnowledgeSession securityContext = getSecurityContext();
      if (securityContext == null) return false;
      
      RoleCheck roleCheck = new RoleCheck(roleName);
      
      List<FactHandle> handles = new ArrayList<FactHandle>();
      PermissionCheck check = new PermissionCheck(target, action);
      
      synchronized( securityContext )
      {
         if (!(target instanceof String) && !(target instanceof Class))
         {
            handles.add( securityContext.insert(target) );
         }
         else if (target instanceof Class)
         {
            // TODO fix
            String componentName = null; //Seam.getComponentName((Class) target);
            target = componentName != null ? componentName : ((Class) target).getName();
         }
         
         try
         {
            handles.add( securityContext.insert(check));
            
            // Check if there are any additional requirements
            securityContext.fireAllRules();
            if (check.hasRequirements())
            {
               for (String requirement : check.getRequirements())
               {
                  // TODO fix
                  Object value = null; // Contexts.lookupInStatefulContexts(requirement);
                  if (value != null)
                  {
                     handles.add (securityContext.insert(value));
                  }
               }
            }
            
            synchronizeContext();

            handles.add( securityContext.insert(roleCheck));
            handles.add( securityContext.insert(check));
            
            securityContext.fireAllRules();
         }
         finally
         {
            for (FactHandle handle : handles)
            {
               securityContext.retract(handle);
            }
         }
      }
      
      return roleCheck.isGranted();
   }
   
   @SuppressWarnings("unchecked")
   public void unAuthenticate(@Observes LoggedOutEvent event)
   {
      if (getSecurityContext() != null)
      {
         getSecurityContext().dispose();
         setSecurityContext(null);
      }
      initSecurityContext();
   }
   
   /**
    *  Synchronises the state of the security context with that of the subject
    */
   private void synchronizeContext()
   {
      if (getSecurityContext() != null)
      {
         getSecurityContext().insert(identity.getPrincipal());
         
         for ( Group sg : identity.getSubject().getPrincipals(Group.class) )
         {
            if ( IdentityImpl.ROLES_GROUP.equals( sg.getName() ) )
            {
               Enumeration e = sg.members();
               while (e.hasMoreElements())
               {
                  Principal role = (Principal) e.nextElement();
   
                  boolean found = false;
                  Iterator<?> iter = getSecurityContext().getObjects(new ClassObjectFilter(Role.class)).iterator();
                  while (iter.hasNext())
                  {
                     Role r = (Role) iter.next();
                     if (r.getName().equals(role.getName()))
                     {
                        found = true;
                        break;
                     }
                  }
                  
                  if (!found)
                  {
                     getSecurityContext().insert(new Role(role.getName()));
                  }
                  
               }
            }
         }
         
         Iterator<?> iter = getSecurityContext().getObjects(new ClassObjectFilter(Role.class)).iterator();
         while (iter.hasNext())
         {
            Role r = (Role) iter.next();
            if (!identity.hasRole(r.getName()))
            {
               FactHandle fh = getSecurityContext().getFactHandle(r);
               getSecurityContext().retract(fh);
            }
         }
      }
   }
   
   
   public StatefulKnowledgeSession getSecurityContext()
   {
      return securityContext;
   }
   
   public void setSecurityContext(StatefulKnowledgeSession securityContext)
   {
      this.securityContext = securityContext;
   }
   

   public KnowledgeBase getSecurityRules()
   {
      return securityRules;
   }

   public void setSecurityRules(KnowledgeBase securityRules)
   {
      this.securityRules = securityRules;
   }
   
   /**
    * Post-authentication event observer
    */
   public void setUserAccountInSecurityContext(@Observes PostAuthenticateEvent event)
   {
      if (getSecurityContext() != null)
      {
         getSecurityContext().insert(identity.getPrincipal());

         // If we were authenticated with the JpaIdentityStore, then insert the authenticated
         // UserAccount into the security context.
         
         // TODO fix
         /*if (Contexts.isEventContextActive() && Contexts.isSessionContextActive() &&
               Contexts.getEventContext().isSet(JpaIdentityStore.AUTHENTICATED_USER))
         {
            getSecurityContext().insert(Contexts.getEventContext().get(JpaIdentityStore.AUTHENTICATED_USER));
         }*/
      }
   }
}
