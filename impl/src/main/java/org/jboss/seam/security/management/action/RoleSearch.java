package org.jboss.seam.security.management.action;

import java.io.Serializable;

import javax.enterprise.context.SessionScoped;
import javax.inject.Named;

@Named
@SessionScoped
public class RoleSearch implements Serializable
{
   private static final long serialVersionUID = -1014495134519417515L;

   /*
   @DataModel
   List<String> roles;
   
   @DataModelSelection
   String selectedRole;
   
   @Current IdentityManager identityManager;
   
   public void loadRoles()
   {
      roles = identityManager.listRoles();
   }
   
   public String getRoleGroups(String role)
   {
      List<String> roles = identityManager.getRoleGroups(role);
      
      if (roles == null) return "";
      
      StringBuilder sb = new StringBuilder();
      
      for (String r : roles)
      {
         sb.append((sb.length() > 0 ? ", " : "") + r);
      }
      
      return sb.toString();
   }
   
   public String getSelectedRole()
   {
      return selectedRole;
   }
   
   */
}