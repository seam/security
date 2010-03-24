package org.jboss.seam.security.events;

import java.security.Principal;

/**
 * This event is raised when user successfully logs in.
 *  
 * @author Shane Bryzak
 */
public class LoggedInEvent
{
   private Principal principal;
   
   public LoggedInEvent(Principal principal)
   {
      this.principal = principal;
   }
   
   public Principal getPrincipal()
   {
      return principal;
   }
}
