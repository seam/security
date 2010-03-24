package org.jboss.seam.security.events;

import java.security.Principal;

/**
 * This event is raised just after the user unauthenticates
 * 
 * @author Shane Bryzak
 */
public class LoggedOutEvent
{
   private Principal principal;
   
   public LoggedOutEvent(Principal principal)
   {
      this.principal = principal;
   }
   
   public Principal getPrincipal()
   {
      return principal;
   }
}
