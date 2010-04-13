package org.jboss.seam.security;

import java.io.Serializable;
import java.security.Principal;

/**
 * Simple implementation of the Principal interface, supporting a named user.
 * 
 * @author Shane Bryzak
 */
public class SimplePrincipal implements Principal, Serializable
{
   private static final long serialVersionUID = 5609375932836425908L;   
   
   private String name;
   
   public SimplePrincipal(String name)
   {
      this.name = name;
   }
   
   public String getName()
   {
      return name;
   }

   @Override
   public boolean equals(Object obj)
   {
      if (obj instanceof Principal)
      {
         Principal other = (Principal) obj;
         return name == null ?
                  other.getName() == null :
                  name.equals( other.getName() );
      }
      else
      {
         return false;
      }
   }

   @Override
   public int hashCode()
   {
      return name != null ? name.hashCode() : super.hashCode();
   }

   @Override
   public String toString()
   {
      return name;
   }   
}
