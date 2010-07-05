package org.jboss.seam.security.management.action;

import java.io.Serializable;
import java.util.ArrayList;
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

   List<UserDTO> users;
      
   @Inject IdentityManager identityManager;
   
   @Inject public void loadUsers()
   {       
      users = new ArrayList<UserDTO>();
      
      List<String> usernames = identityManager.findUsers(null);  
      for (String username : usernames)
      {
         UserDTO dto = new UserDTO();
         dto.setUsername(username);
         dto.setEnabled(identityManager.isUserEnabled(username));
         users.add(dto);
      }      
   }
   
   public String getUserRoles(String username)
   {
      // TODO rewrite
      //List<String> roles = identityManager.getGrantedRoles(username);
      
      //if (roles == null) return "";
      
      StringBuilder sb = new StringBuilder();
      
      //for (String role : roles)
      //{
      //   sb.append((sb.length() > 0 ? ", " : "") + role);
      //}
      
      return sb.toString();
   }
   
   //public String getSelectedUser()
   //{
      //return selectedUser;
   //}
   
   public List<UserDTO> getUsers()
   {
      return users;
   }   
   
}