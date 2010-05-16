package org.jboss.seam.security;

/**
 * Seam implementation of the PicketLink RoleType interface.  A RoleType is
 * essentially the name of a particular role.  E.g. manager, user, superuser, etc.
 * 
 * @author Shane Bryzak
 */
public class RoleType implements org.picketlink.idm.api.RoleType
{
   private String name;
   
   public RoleType(String name)
   {
      this.name = name;
   }
   
   public String getName()
   {
      return name;
   }

}
