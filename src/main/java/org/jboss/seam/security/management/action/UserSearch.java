package org.jboss.seam.security.management.action;

import java.io.Serializable;

import javax.enterprise.context.SessionScoped;
import javax.inject.Named;

@Named
@SessionScoped
public class UserSearch implements Serializable
{
   private static final long serialVersionUID = 8592034786339372510L;

   /*
   @DataModel
   List<String> users;
   
   @DataModelSelection
   String selectedUser;
   
   @Current IdentityManager identityManager;
   
   public void loadUsers()
   {
      users = identityManager.listUsers();
   }
   
   public String getUserRoles(String username)
   {
      List<String> roles = identityManager.getGrantedRoles(username);
      
      if (roles == null) return "";
      
      StringBuilder sb = new StringBuilder();
      
      for (String role : roles)
      {
         sb.append((sb.length() > 0 ? ", " : "") + role);
      }
      
      return sb.toString();
   }
   
   public String getSelectedUser()
   {
      return selectedUser;
   }
   
   */
}