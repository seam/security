package org.jboss.seam.security.events;

import org.jboss.seam.security.permission.ResolverChain;

/**
 * This event is raised when the default permission resolver chain is created
 *  
 * @author Shane Bryzak
 */
public class DefaultResolverChainCreatedEvent
{
   private ResolverChain chain;
   
   public DefaultResolverChainCreatedEvent(ResolverChain chain)
   {
      this.chain = chain;
   }
   
   public ResolverChain getChain()
   {
      return chain;
   }
}
