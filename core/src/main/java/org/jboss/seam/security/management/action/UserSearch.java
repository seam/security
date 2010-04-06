package org.jboss.seam.security.management.action;

import java.io.Serializable;
import java.util.List;

import javax.enterprise.context.SessionScoped;
import javax.inject.Inject;
import javax.inject.Named;

import org.jboss.seam.security.management.IdentityManager;

@Named
@SessionScoped
public class UserSearch implements Serializable
{
   private static final long serialVersionUID = 8592034786339372510L;

   List<String> users;
   
   //@DataModelSelection
   //String selectedUser;
   
   @Inject IdentityManager identityManager;
   
   public void loadUsers()
   {
      users = identityManager.getUsers();
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
   
   //public String getSelectedUser()
   //{
      //return selectedUser;
   //}
   
   public List<String> getUsers()
   {
      return users;
   }   
   
}