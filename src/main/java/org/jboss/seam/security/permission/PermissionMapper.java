package org.jboss.seam.security.permission;

import java.io.Serializable;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.enterprise.inject.spi.Bean;
import javax.enterprise.inject.spi.BeanManager;

import org.jboss.seam.beans.BeanManagerHelper;
import org.jboss.seam.security.events.DefaultResolverChainCreatedEvent;

/**
 * Maps permission checks to resolver chains
 * 
 * @author Shane Bryzak
 */
@ApplicationScoped
public class PermissionMapper implements Serializable
{
   public static final String DEFAULT_RESOLVER_CHAIN_CREATED = "org.jboss.seam.security.defaultResolverChainCreated";
   
   private Map<Class,Map<String,String>> resolverChains = new HashMap<Class,Map<String,String>>();
   
   private String defaultResolverChain;
   
   private static final String DEFAULT_RESOLVER_CHAIN = "org.jboss.seam.security.defaultResolverChain";
   
   @Inject BeanManager manager;
   
   private ResolverChain getResolverChain(Object target, String action)
   {
      Class targetClass = null;
      
      if (target instanceof Class)
      {
         targetClass = (Class) target;
      }
      else
      {
         // TODO target may be a component name, or an object, or a view name (or arbitrary name) -
         // we need to deal with all of these possibilities
      }
      
      if (targetClass != null)
      {
         Map<String,String> chains = resolverChains.get(target);
         if (chains != null && chains.containsKey(action))
         {
                return (ResolverChain) BeanManagerHelper.getInstanceByName(manager, chains.get(action));
         }
      }
      
      if (defaultResolverChain != null && !"".equals(defaultResolverChain))
      {
         return (ResolverChain) BeanManagerHelper.getInstanceByName(manager,defaultResolverChain);
      }
      
      return createDefaultResolverChain();
   }
   
   public boolean resolvePermission(Object target, String action)
   {
      ResolverChain chain = getResolverChain(target, action);
      for (PermissionResolver resolver : chain.getResolvers())
      {
         if (resolver.hasPermission(target, action))
         {
            return true;
         }
      }
      
      return false;
   }
   
   public void filterByPermission(Collection collection, String action)
   {
      boolean homogenous = true;
      
      Class targetClass = null;
      for (Object target : collection)
      {
         if (targetClass == null) targetClass = target.getClass();
         if (!targetClass.equals(target.getClass()))
         {
            homogenous = false;
            break;
         }
      }
           
      if (homogenous)
      {
         Set<Object> denied = new HashSet<Object>(collection);
         ResolverChain chain = getResolverChain(targetClass, action);
         for (PermissionResolver resolver : chain.getResolvers())
         {
            resolver.filterSetByAction(denied, action);
         }
         
         for (Object target : denied)
         {
            collection.remove(target);
         }
      }
      else
      {
         Map<Class,Set<Object>> deniedByClass = new HashMap<Class,Set<Object>>();
         for (Object obj : collection)
         {
            if (!deniedByClass.containsKey(obj.getClass()))
            {
               Set<Object> denied = new HashSet<Object>();
               denied.add(obj);
               deniedByClass.put(obj.getClass(), denied);
            }
            else
            {
               deniedByClass.get(obj.getClass()).add(obj);
            }
         }
         
         for (Class cls : deniedByClass.keySet())
         {
            Set<Object> denied = deniedByClass.get(cls);
            ResolverChain chain = getResolverChain(cls, action);
            for (PermissionResolver resolver : chain.getResolvers())
            {
               resolver.filterSetByAction(denied, action);
            }
            
            for (Object target : denied)
            {
               collection.remove(target);
            }
         }
      }
   }
   
   private ResolverChain createDefaultResolverChain()
   {
      // TODO fix
      ResolverChain chain = null; //(ResolverChain) Contexts.getSessionContext().get(DEFAULT_RESOLVER_CHAIN);
      
      if (chain == null)
      {
         chain = new ResolverChain();
         
         Set<Bean<?>> resolvers = manager.getBeans(PermissionResolver.class);
         for (Bean<?> resolverBean :  resolvers)
         {
            chain.getResolvers().add((PermissionResolver) manager.getReference(resolverBean, PermissionResolver.class, manager.createCreationalContext(resolverBean)));
         }
         
         // TODO fix
         // Contexts.getSessionContext().set(DEFAULT_RESOLVER_CHAIN, chain);
         
         manager.fireEvent(new DefaultResolverChainCreatedEvent(chain));
      }
      
      return chain;
   }
}
