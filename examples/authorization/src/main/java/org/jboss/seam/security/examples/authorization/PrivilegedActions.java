package org.jboss.seam.security.examples.authorization;

import javax.enterprise.inject.Model;

import org.jboss.seam.security.annotations.LoggedIn;
import org.jboss.seam.security.examples.authorization.annotations.Admin;
import org.jboss.seam.security.examples.authorization.annotations.Foo;

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
   
   @Foo(bar = "abc", zzz="nonbindingvalue")
   public void doFooAbc()
   {
      System.out.println("doFooAbc() invoked");
   }
   
   @Foo(bar = "def")
   public void doFooDef()
   {
      System.out.println("doFooDef() invoked");
   }
   
   @LoggedIn
   public void doLoggedIn()
   {
      System.out.println("doLoggedIn() invoked");
   }
}
