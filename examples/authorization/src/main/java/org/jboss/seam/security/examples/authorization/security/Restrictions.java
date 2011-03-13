package org.jboss.seam.security.examples.authorization.security;

import org.jboss.seam.security.Identity;
import org.jboss.seam.security.annotations.Secures;
import org.jboss.seam.security.examples.authorization.annotations.Admin;
import org.jboss.seam.security.examples.authorization.annotations.Foo;

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
   
   public @Secures @Foo(bar = "abc") boolean isFooAbc()
   {
      System.out.println("isFooAbc() invoked");
      return true;
   }
   
   public @Secures @Foo(bar = "def") boolean isFooDef()
   {
      System.out.println("isFooDef() invoked");
      return true;
   }
}
