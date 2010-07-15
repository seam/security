package org.jboss.seam.security;

import org.picketlink.idm.api.User;

/**
 * Simple implementation of user
 * 
 * @author Shane Bryzak
 *
 */
public class UserImpl implements User
{
   private String id;
   
   public UserImpl(String id)
   {
      this.id = id;
   }
   
   public String getId()
   {
      return id;
   }

   public String getKey()
   {
      return id;
   }
}
