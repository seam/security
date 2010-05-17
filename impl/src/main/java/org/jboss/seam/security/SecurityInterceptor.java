package org.jboss.seam.security;

import java.io.Serializable;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.inject.Inject;
import javax.enterprise.inject.spi.Bean;
import javax.enterprise.inject.spi.BeanManager;
import javax.interceptor.AroundInvoke;
import javax.interceptor.Interceptor;
import javax.interceptor.InvocationContext;

import org.jboss.seam.security.annotations.PermissionCheck;
import org.jboss.seam.security.annotations.Restrict;
import org.jboss.seam.security.annotations.RoleCheck;
import org.jboss.seam.security.util.Strings;

/**
 * Provides authorization services for component invocations.
 * 
 * @author Shane Bryzak
 */
@Secure @Interceptor
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
   
   private class Restriction
   {
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
               
               Restrict restrict = null;
               
               if ( interfaceMethod.isAnnotationPresent(Restrict.class) )
               {
                  restrict = interfaceMethod.getAnnotation(Restrict.class);
               }
               else if ( interfaceMethod.getDeclaringClass().isAnnotationPresent(Restrict.class) )
               {
                   restrict = interfaceMethod.getDeclaringClass().getAnnotation(Restrict.class);
               }
               
               if (restrict != null)
               {
                  if (restriction == null) restriction = new Restriction();
                  
                  if ( Strings.isEmpty(restrict.value()) )
                  {
                     Bean<?> bean = manager.getBeans(interfaceMethod.getDeclaringClass()).iterator().next();
                     restriction.setPermissionTarget(bean.getName());
                     restriction.setPermissionAction(interfaceMethod.getName());
                  }
                  else
                  {
                     restriction.setExpression(restrict.value());
                  }
               }
               
               for (Annotation annotation : interfaceMethod.getDeclaringClass().getAnnotations())
               {
                  if (annotation.annotationType().isAnnotationPresent(RoleCheck.class))
                  {
                     if (restriction == null) restriction = new Restriction();
                     restriction.addRoleRestriction(annotation.annotationType().getSimpleName().toLowerCase());
                  }
               }
               
               for (Annotation annotation : interfaceMethod.getAnnotations())
               {
                  if (annotation.annotationType().isAnnotationPresent(PermissionCheck.class))
                  {
                     PermissionCheck permissionCheck = annotation.annotationType().getAnnotation(
                           PermissionCheck.class);
                     
                     Method valueMethod = null;
                     for (Method m : annotation.annotationType().getDeclaredMethods())
                     {
                        valueMethod = m;
                        break;
                     }
                     
                     if (valueMethod != null)
                     {
                        if (restriction == null) restriction = new Restriction();
                        Object target = valueMethod.invoke(annotation);
                        if (!target.equals(void.class))
                        {
                           if (restriction == null) restriction = new Restriction();
                           restriction.addMethodRestriction(target,
                                 getPermissionAction(permissionCheck, annotation));
                        }
                     }
                  }
                  if (annotation.annotationType().isAnnotationPresent(RoleCheck.class))
                  {
                     if (restriction == null) restriction = new Restriction();
                     restriction.addRoleRestriction(annotation.annotationType().getSimpleName().toLowerCase());
                  }
               }
               
               for (int i = 0; i < interfaceMethod.getParameterAnnotations().length; i++)
               {
                  Annotation[] annotations = interfaceMethod.getParameterAnnotations()[i];
                  for (Annotation annotation : annotations)
                  {
                     if (annotation.annotationType().isAnnotationPresent(PermissionCheck.class))
                     {
                        PermissionCheck permissionCheck = annotation.annotationType().getAnnotation(
                              PermissionCheck.class);
                        if (restriction == null) restriction = new Restriction();
                        restriction.addParameterRestriction(i,
                              getPermissionAction(permissionCheck, annotation));
                     }
                  }
               }
               
               restrictions.put(interfaceMethod, restriction);
               return restriction;
            }
         }
      }
      return restrictions.get(interfaceMethod);
   }

   
   private String getPermissionAction(PermissionCheck check, Annotation annotation)
   {
      if (!"".equals(check.value()))
      {
         return check.value();
      }
      else
      {
         return annotation.annotationType().getSimpleName().toLowerCase();
      }
   }
}
