package org.jboss.seam.security.events;

import java.security.Principal;

/**
 * This event is raised just after the user unauthenticates
 * 
 * @author Shane Bryzak
 */
public class PostLoggedOutEvent
{
   private Principal principal;
   
   public PostLoggedOutEvent(Principal principal)
   {
      this.principal = principal;
   }
   
   public Principal getPrincipal()
   {
      return principal;
   }
}
