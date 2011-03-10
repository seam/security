package org.jboss.seam.security.examples.authorization.security;

import org.jboss.seam.security.Identity;
import org.jboss.seam.security.annotations.Secures;
import org.jboss.seam.security.examples.authorization.annotations.Admin;

/**
 * 
 * @author Shane Bryzak
 *
 */
public class Restrictions
{
   public @Secures @Admin boolean isAdmin(Identity identity)
   {
      return identity.hasRole("admin", "USERS", "USER");
   }
}
