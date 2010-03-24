package org.jboss.seam.security;

/**
 * Represents a user role.  A conditional role is a special type of role that is assigned to a user
 * based on the contextual state of a permission check.
 *  
 * @author Shane Bryzak
 */
public class Role extends SimplePrincipal
{   
   private static final long serialVersionUID = 1187276024036531700L;
   
   private boolean conditional;
   
   public Role(String name)
   {
      super(name);
   }   
   
   public Role(String name, boolean conditional)
   {
      this(name);
      this.conditional = conditional;
   }
   
   public boolean isConditional()
   {
      return conditional;
   }
}
