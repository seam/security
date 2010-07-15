package org.jboss.seam.security.management.action;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.enterprise.context.SessionScoped;
import javax.inject.Inject;
import javax.inject.Named;

import org.jboss.seam.security.management.IdentityManager;
import org.picketlink.idm.api.Role;
import org.picketlink.idm.api.User;

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
      
      Collection<User> results = identityManager.findUsers(null);  
      for (User user : results)
      {
         UserDTO dto = new UserDTO();
         dto.setUsername(user.getId());
         dto.setEnabled(identityManager.isUserEnabled(user.getId()));
         users.add(dto);
      }      
   }
   
   public String getUserRoles(String username)
   {
      Collection<Role> roles = identityManager.getGrantedRoles(username);
      
      //if (roles == null) return "";
      
      StringBuilder sb = new StringBuilder();
      
      for (Role role : roles)
      {
         sb.append((sb.length() > 0 ? ", " : "") + role.getRoleType().getName() + 
               ":" + role.getGroup().getName());
      }
      
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