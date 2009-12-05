package org.jboss.seam.security.permission;

import java.io.Serializable;

/**
 * Used when performing rule-based conditional role checks
 * 
 * @author Shane Bryzak
 */
public class RoleCheck implements Serializable
{
   private String name;
   private boolean granted;
   
   public RoleCheck(String name)
   {
      this.name = name;
   }
   
   public boolean isGranted()
   {
      return granted;
   }
   
   public void grant()
   {
      this.granted = true;
   }
   
   public void revoke()
   {
      this.granted = false;
   }
   
   public String getName()
   {
      return name;
   }
}
