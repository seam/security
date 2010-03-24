package org.jboss.seam.security.permission;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import javax.enterprise.context.SessionScoped;

/**
 * A chain of permission resolvers.  Specific permission checks are generally mapped to a
 * particular ResolverChain for resolution.
 * 
 * @author Shane Bryzak
 */
@SessionScoped
public class ResolverChain implements Serializable
{
   private static final long serialVersionUID = 4395507285094476740L;
   
   private List<PermissionResolver> resolvers = new ArrayList<PermissionResolver>();
   
   public List<PermissionResolver> getResolvers()
   {
      return resolvers;
   }
   
   public void setResolvers(List<PermissionResolver> resolvers)
   {
      this.resolvers = resolvers;
   }
}
