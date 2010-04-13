package org.jboss.seam.security.permission;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.context.SessionScoped;
import javax.inject.Inject;
import javax.enterprise.inject.Produces;
import javax.enterprise.inject.spi.Bean;
import javax.enterprise.inject.spi.BeanManager;

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
   
   private List<PermissionResolver> getResolvers(Object target, String action)
   {
      Class<?> targetClass = null;
      
      if (target instanceof Class)
      {
         targetClass = (Class) target;
      }
      else
      {
         // TODO target may be a component name, or an object, or a view name (or arbitrary name) -
         // we need to deal with all of these possibilities
      }
      
      // TODO configure resolver chains differently - scan for all beans of type ResolverChain
      
      /*
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
      */
      
      return createDefaultResolverChain();
   }
   
   public boolean resolvePermission(Object target, String action)
   {
      List<PermissionResolver> resolvers = getResolvers(target, action);
      for (PermissionResolver resolver : resolvers)
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
         List<PermissionResolver> resolvers = getResolvers(targetClass, action);
         for (PermissionResolver resolver : resolvers)
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
            List<PermissionResolver> resolvers = getResolvers(cls, action);
            for (PermissionResolver resolver : resolvers)
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
   
   @Produces public @SessionScoped List<PermissionResolver> createDefaultResolverChain()
   {
      List<PermissionResolver> resolvers = new ArrayList<PermissionResolver>();
               
      Set<Bean<?>> beans = manager.getBeans(PermissionResolver.class);
      for (Bean<?> resolverBean :  beans)
      {
         resolvers.add((PermissionResolver) manager.getReference(resolverBean, PermissionResolver.class, manager.createCreationalContext(resolverBean)));
      }
      
      return resolvers;
   }
}
