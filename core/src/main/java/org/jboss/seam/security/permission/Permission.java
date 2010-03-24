package org.jboss.seam.security.permission;

import java.io.Serializable;
import java.security.Principal;

/**
 * Represents a single permission for a particular target, action and recipient combination.
 *  
 * @author Shane Bryzak
 */
public class Permission implements Serializable
{
   private Object target;
   private String action;
   private Principal recipient;
   
   public Permission(Object target, String action, Principal recipient)
   {
      this.target = target;
      this.action = action;
      this.recipient = recipient;
   }
   
   public Object getTarget()
   {
      return target;
   }
   
   public String getAction()
   {
      return action;
   }
   
   public Principal getRecipient()
   {
      return recipient;
   }
}
