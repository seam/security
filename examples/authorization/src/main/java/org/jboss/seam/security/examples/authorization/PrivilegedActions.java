package org.jboss.seam.security.examples.authorization;

import org.jboss.seam.security.examples.authorization.annotations.Admin;

/**
 * 
 * @author Shane Bryzak
 *
 */
public class PrivilegedActions
{
   @Admin
   public void doSomethingRestricted()
   {
      System.out.println("doSomethingRestricted() invoked");
   }
}
