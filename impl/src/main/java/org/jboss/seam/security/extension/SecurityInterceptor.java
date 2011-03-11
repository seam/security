package org.jboss.seam.security.extension;

import java.io.Serializable;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.enterprise.inject.spi.BeanManager;
import javax.inject.Inject;
import javax.interceptor.AroundInvoke;
import javax.interceptor.Interceptor;
import javax.interceptor.InvocationContext;

import org.jboss.seam.security.Identity;
import org.jboss.seam.security.IdentityImpl;

/**
 * Provides authorization services for component invocations.
 * 
 * @author Shane Bryzak
 */
@SecurityInterceptorBinding @Interceptor
public class SecurityInterceptor implements Serializable
{
   private static final long serialVersionUID = -6567750187000766925L;
   
   /**
    * You may encounter a JVM bug where the field initializer is not evaluated for a transient field after deserialization.
    * @see "http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=6252102"
    */
   private transient volatile Map<Method,Restriction> restrictions = new HashMap<Method,Restriction>();
   
   @Inject BeanManager manager;
   @Inject Identity identity;
   
   @Inject SecurityExtension extension;
   
   private class Restriction
   {
      @SuppressWarnings("unused")
      private String expression;
      
      private String permissionTarget;
      private String permissionAction;
      
      private Map<String, Object> methodRestrictions;
      private Map<Integer,Set<String>> paramRestrictions;
      private Set<String> roleRestrictions;
            
      public void setExpression(String expression)
      {
         this.expression = expression;
      }
      
      public void setPermissionTarget(String target)
      {
         this.permissionTarget = target;
      }
      
      public void setPermissionAction(String action)
      {
         this.permissionAction = action;
      }
      
      public void addMethodRestriction(Object target, String action)
      {
         if (methodRestrictions == null)
         {
            methodRestrictions = new HashMap<String, Object>();
         }
         
         methodRestrictions.put(action, target);
      }
      
      public void addRoleRestriction(String role)
      {
         if (roleRestrictions == null)
         {
            roleRestrictions = new HashSet<String>();
         }
         
         roleRestrictions.add(role);
      }
      
      public void addParameterRestriction(int index, String action)
      {
         Set<String> actions = null;
         
         if (paramRestrictions == null)
         {
            paramRestrictions = new HashMap<Integer,Set<String>>();
         }
         
         if (!paramRestrictions.containsKey(index))
         {
            actions = new HashSet<String>();
            paramRestrictions.put(index, actions);
         }
         else
         {
            actions = paramRestrictions.get(index);
         }
         
         actions.add(action);
      }
      
      public void check(Identity identity, Object[] parameters)
      {
         if (IdentityImpl.isSecurityEnabled())
         {
            // TODO rewrite EL based restrictions
            /*if (expression != null)
            {
               identity.checkRestriction(expression);
            }*/
            
            if (methodRestrictions != null)
            {
               for (String action : methodRestrictions.keySet())
               {
                  identity.checkPermission(methodRestrictions.get(action), action);
               }
            }
            
            if (paramRestrictions != null)
            {
               for (Integer idx : paramRestrictions.keySet())
               {
                  Set<String> actions = paramRestrictions.get(idx);
                  for (String action : actions)
                  {
                     identity.checkPermission(parameters[idx], action);
                  }
               }
            }
            
            if (roleRestrictions != null)
            {
               // TODO rewrite role restriction logic
               //for (String role : roleRestrictions)
               //{
               //   identity.checkRole(role);
               //}
            }
            
            if (permissionTarget != null && permissionAction != null)
            {
               identity.checkPermission(permissionTarget, permissionAction);
            }
         }
      }
   }
   
   @AroundInvoke
   public Object aroundInvoke(InvocationContext invocation) throws Exception
   {
      System.out.println("SecurityInterceptor invoked");
      
      Method interfaceMethod = invocation.getMethod();
      
      if (!"hashCode".equals(interfaceMethod.getName()))
      {
         Restriction restriction = getRestriction(interfaceMethod);
         if ( restriction != null )
         {
            
            restriction.check(identity, invocation.getParameters());
         }
      }

      return invocation.proceed();
   }
   
   private Restriction getRestriction(Method interfaceMethod) throws Exception
   {
      // see field declaration as to why this is done
      if (restrictions == null)
      {
         synchronized(this)
         {
            restrictions = new HashMap<Method, Restriction>();
         }
      }
      
      if (!restrictions.containsKey(interfaceMethod))
      {
         synchronized(restrictions)
         {
            // FIXME this logic should be abstracted rather than sitting in the middle of this interceptor
            if (!restrictions.containsKey(interfaceMethod))
            {
               Restriction restriction = null;
               
               /*Method method = getComponent().getBeanClass().getMethod(
                     interfaceMethod.getName(), interfaceMethod.getParameterTypes() );*/
               
               
               restrictions.put(interfaceMethod, restriction);
               return restriction;
            }
         }
      }
      return restrictions.get(interfaceMethod);
   }

}
