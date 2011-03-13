package org.jboss.seam.security.extension;

import java.lang.annotation.Annotation;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.enterprise.event.Observes;
import javax.enterprise.inject.spi.AfterBeanDiscovery;
import javax.enterprise.inject.spi.AnnotatedMethod;
import javax.enterprise.inject.spi.AnnotatedType;
import javax.enterprise.inject.spi.BeanManager;
import javax.enterprise.inject.spi.Extension;
import javax.enterprise.inject.spi.ProcessAnnotatedType;
import javax.enterprise.util.Nonbinding;

import org.jboss.seam.security.SecurityDefinitionException;
import org.jboss.seam.security.annotations.Secures;
import org.jboss.seam.security.annotations.SecurityBindingType;
import org.jboss.seam.solder.reflection.annotated.AnnotatedTypeBuilder;

/**
 * Extension for typesafe security annotations
 * 
 * @author Shane Bryzak
 *
 */
public class SecurityExtension implements Extension
{
   class Authorizer
   {
      private Annotation binding;
      private Map<Method,Object> memberValues = new HashMap<Method,Object>();
      
      private Method implementationMethod;
      
      public Authorizer(Annotation binding, Method implementationMethod)
      {
         this.binding = binding;
         this.implementationMethod = implementationMethod;

         try
         {
            for (Method m : binding.annotationType().getDeclaredMethods())
            {
               if (m.isAnnotationPresent(Nonbinding.class)) continue;
               memberValues.put(m, m.invoke(binding));
            }
         }
         catch (InvocationTargetException ex)
         {
            throw new SecurityDefinitionException("Error reading security binding members", ex);
         }
         catch (IllegalAccessException ex)
         {
            throw new SecurityDefinitionException("Error reading security binding members", ex);
         }
      }
      
      public boolean matchesBinding(Annotation annotation) 
      {
         if (!annotation.annotationType().equals(binding.annotationType()))
         {
            return false;
         }
         
         for (Method m : annotation.annotationType().getDeclaredMethods())
         {
            if (m.isAnnotationPresent(Nonbinding.class)) continue;
            
            if (!memberValues.containsKey(m))
            {
               return false;
            }
            
            try
            {
               Object value = m.invoke(annotation);
               if (!memberValues.get(m).equals(value))
               {
                  return false;
               }
            }
            catch (InvocationTargetException ex)
            {
               throw new SecurityDefinitionException("Error reading security binding members", ex);
            }
            catch (IllegalAccessException ex)
            {
               throw new SecurityDefinitionException("Error reading security binding members", ex);
            }
         }
         
         return true;
      }
      
      public Method getImplementationMethod()
      {
         return implementationMethod;
      }
      
      @Override
      public boolean equals(Object value)
      {
         return false;
      }
      
      @Override
      public int hashCode()
      {
         return 0;
      }
   }
   
   /**
    * Contains all known authorizers
    */
   private Set<Authorizer> authorizers = new HashSet<Authorizer>();
   
   /**
    * Contains all known secured types
    */
   private Set<AnnotatedType<?>> securedTypes = new HashSet<AnnotatedType<?>>();
   
   /**
    * A mapping between a secured method and its authorizers
    */
   private Map<Method,Set<Authorizer>> methodAuthorizers = new HashMap<Method,Set<Authorizer>>();
   
   public <X> void processAnnotatedType(@Observes ProcessAnnotatedType<X> event, 
         final BeanManager beanManager)
   {
      AnnotatedTypeBuilder<X> builder = null;
      AnnotatedType<X> type = event.getAnnotatedType();
      
      boolean isSecured = false;
      
      // Add the security interceptor to the class if the class is annotated
      // with a security binding type
      for (final Annotation annotation : type.getAnnotations())
      {
         if (annotation.annotationType().isAnnotationPresent(SecurityBindingType.class))
         {
            builder = new AnnotatedTypeBuilder<X>().readFromType(type);
            builder.addToClass(SecurityInterceptorBindingLiteral.INSTANCE);
            isSecured = true;
         }
      }
      
      // If the class isn't annotated with a security binding type, check if
      // any of its methods are, and if so, add the security interceptor to the
      // method
      if (!isSecured)
      {
         for (final AnnotatedMethod<? super X> m : type.getMethods())
         {
            if (m.isAnnotationPresent(Secures.class)) 
            {
               registerAuthorizer(m);
               continue;
            }
            
            for (final Annotation annotation : m.getAnnotations())
            {
               if (annotation.annotationType().isAnnotationPresent(SecurityBindingType.class))
               {
                  if (builder == null)
                  {
                     builder = new AnnotatedTypeBuilder<X>().readFromType(type);
                     builder.addToMethod(m, SecurityInterceptorBindingLiteral.INSTANCE);
                     isSecured = true;
                  }                  
               }
            }
         }         
      }
      
      // If either the bean or any of its methods are secured, register it
      if (isSecured)
      {
         securedTypes.add(type);
      }
      
      if (builder != null)
      {
         event.setAnnotatedType(builder.create());
      }
      
   }
   
   public void validateBindings(@Observes AfterBeanDiscovery event) 
   {
      for (final AnnotatedType<?> type : securedTypes)
      {
         // Here we simply want to validate that each type that is annotated with
         // one or more security bindings has a valid authorizer for each binding
         
         for (final Annotation annotation : type.getJavaClass().getAnnotations())
         {
            boolean found = false;
            
            if (annotation.annotationType().isAnnotationPresent(SecurityBindingType.class))
            {
               // Validate the authorizer
               for (Authorizer auth : authorizers)
               {
                  if (auth.matchesBinding(annotation))
                  {
                     found = true;
                     break;
                  }
               }
               
               if (!found)
               {
                  event.addDefinitionError(new SecurityDefinitionException("Secured type " +
                        type.getJavaClass().getName() + 
                        " has no matching authorizer method for security binding @" +
                        annotation.annotationType().getName()));
               }
            }
         }
         
         for (final AnnotatedMethod<?> method : type.getMethods())
         {
            for (final Annotation annotation : method.getAnnotations())
            {
               if (annotation.annotationType().isAnnotationPresent(SecurityBindingType.class))
               {
                  registerSecuredMethod(method.getJavaMember());
                  break;
               }
            }            
         }
      }      
      
      // Clear securedTypes, we don't require it any more
      securedTypes.clear();
      securedTypes = null;
   }
   
   protected void registerSecuredMethod(Method method) 
   {
      if (!methodAuthorizers.containsKey(method))
      {
         // Build a list of all security bindings on both the method and its declaring class
         Set<Annotation> bindings = new HashSet<Annotation>();
         
         for (final Annotation annotation : method.getDeclaringClass().getAnnotations())
         {
            if (annotation.annotationType().isAnnotationPresent(SecurityBindingType.class))
            {
               bindings.add(annotation);
            }
         }
         
         for (final Annotation annotation : method.getAnnotations())
         {
            if (annotation.annotationType().isAnnotationPresent(SecurityBindingType.class))
            {
               bindings.add(annotation);
            }
         }
         
         Set<Authorizer> authorizerStack = new HashSet<Authorizer>();
         
         for (Annotation binding : bindings)
         {
            boolean found = false;
            
            // For each security binding, find a valid authorizer
            for (Authorizer authorizer : authorizers)
            {
               if (authorizer.matchesBinding(binding))
               {
                  if (found)
                  {
                     StringBuilder sb = new StringBuilder();
                     sb.append("Matching authorizer methods found: [");
                     sb.append(authorizer.getImplementationMethod().getDeclaringClass().getName());
                     sb.append(".");
                     sb.append(authorizer.getImplementationMethod().getName());
                     sb.append("]");
                     
                     for (Authorizer a : authorizerStack)
                     {
                        if (a.matchesBinding(binding))
                        {
                           sb.append(", [");
                           sb.append(a.getImplementationMethod().getDeclaringClass().getName());
                           sb.append(".");
                           sb.append(a.getImplementationMethod().getName());
                           sb.append("]");                              
                        }
                     }
                     
                     throw new SecurityDefinitionException(
                           "Ambiguous authorizers found for security binding type [@" +
                           binding.annotationType().getName() + "] on method [" +
                           method.getDeclaringClass().getName() + "." +
                           method.getName() + "]. " + sb.toString());
                  }
                  
                  authorizerStack.add(authorizer);
                  found = true;
               }              
            }
            
            if (!found)
            {
               throw new SecurityDefinitionException(
                     "No matching authorizer found for security binding type [@" +
                     binding.annotationType().getName() + "] on method [" +
                     method.getDeclaringClass().getName() + "." +
                     method.getName() + "].");
            }
            
            methodAuthorizers.put(method, authorizerStack);
         }
      }
   }
   
   /**
    * Registers the specified authorizer method (i.e. a method annotated with
    * the @Secures annotation)
    * 
    * @param m
    * @throws IllegalAccessException 
    * @throws InvocationTargetException 
    */
   protected void registerAuthorizer(AnnotatedMethod<?> m) 
   {
      if (!m.getJavaMember().getReturnType().equals(Boolean.class) &&
          !m.getJavaMember().getReturnType().equals(Boolean.TYPE))
      {
         throw new SecurityDefinitionException("Invalid authorizer method [" +
               m.getJavaMember().getDeclaringClass().getName() + "." +
               m.getJavaMember().getName() + "] - does not return a boolean.");
      }
      
      // Locate the binding type
      Annotation binding = null;
      
      for (Annotation a : m.getAnnotations())
      {
         if (a.annotationType().isAnnotationPresent(SecurityBindingType.class))
         {
            if  (binding != null)
            {
               throw new SecurityDefinitionException("Invalid authorizer method [" +
                     m.getJavaMember().getDeclaringClass().getName() + "." +
                     m.getJavaMember().getName() + "] - declares multiple security binding types");
            }
            binding = a;
         }
      }
      
      Authorizer authorizer = new Authorizer(binding, m.getJavaMember());
      authorizers.add(authorizer);
   }
}
