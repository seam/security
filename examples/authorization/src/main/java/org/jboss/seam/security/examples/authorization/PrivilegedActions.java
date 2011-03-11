package org.jboss.seam.security.examples.authorization;

import javax.enterprise.inject.Model;

import org.jboss.seam.security.examples.authorization.annotations.Admin;

/**
 * 
 * @author Shane Bryzak
 *
 */
public @Model class PrivilegedActions
{
   @Admin
   public void doSomethingRestricted()
   {
      System.out.println("doSomethingRestricted() invoked");
   }
}
