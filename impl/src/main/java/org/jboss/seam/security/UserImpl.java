package org.jboss.seam.security;

import org.picketlink.idm.api.User;

/**
 * Implementation of the PicketLink User interface.
 *  
 * @author Shane Bryzak
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
      // TODO Auto-generated method stub
      return null;
   }

}
