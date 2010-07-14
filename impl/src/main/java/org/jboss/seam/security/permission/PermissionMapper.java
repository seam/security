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
import javax.enterprise.context.spi.CreationalContext;
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
   private static final long serialVersionUID = 7692687882996064772L;
  
   private Map<Class<?>,Map<String,String>> resolverChains = new HashMap<Class<?>,Map<String,String>>();
   
   private List<PermissionResolver> defaultResolverChain;
   
   @Inject BeanManager manager;
   
   @Inject
   public void init()
   {
      defaultResolverChain = new ArrayList<PermissionResolver>();
      
      Set<Bean<?>> beans = (Set<Bean<?>>) manager.getBeans(PermissionResolver.class);
      for (Bean<?> resolverBean : beans)
      {         
         CreationalContext<PermissionResolver> ctx = manager.createCreationalContext((Bean<PermissionResolver>) resolverBean);
         defaultResolverChain.add(((Bean<PermissionResolver>) resolverBean).create(ctx));
      }     
   }
   
   private List<PermissionResolver> getResolvers(Object target, String action)
   {
      /*Class<?> targetClass = null;
      
      if (target instanceof Class)
      {
         targetClass = (Class) target;
      }
      else
      {
         // TODO target may be a component name, or an object, or a view name (or arbitrary name) -
         // we need to deal with all of these possibilities
      }
      */
      // TODO more customisation of resolver chains
           
      return defaultResolverChain;
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
   
   public void filterByPermission(Collection<?> collection, String action)
   {
      boolean homogenous = true;
      
      Class<?> targetClass = null;
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
         Map<Class<?>,Set<Object>> deniedByClass = new HashMap<Class<?>,Set<Object>>();
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
         
         for (Class<?> cls : deniedByClass.keySet())
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
}
