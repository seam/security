package org.jboss.seam.security.extension;

import java.lang.annotation.Annotation;

import javax.enterprise.event.Observes;
import javax.enterprise.inject.spi.AnnotatedMethod;
import javax.enterprise.inject.spi.AnnotatedType;
import javax.enterprise.inject.spi.BeanManager;
import javax.enterprise.inject.spi.Extension;
import javax.enterprise.inject.spi.ProcessAnnotatedType;

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
   public <X> void processAnnotatedType(@Observes ProcessAnnotatedType<X> event, 
         final BeanManager beanManager)
   {
      AnnotatedTypeBuilder<X> builder = null;
      AnnotatedType<X> type = event.getAnnotatedType();
      
      boolean isSecured = false;
      
      for (final Annotation annotation : type.getAnnotations())
      {
         if (annotation.annotationType().isAnnotationPresent(SecurityBindingType.class))
         {
            System.out.println("Security binding [" + annotation + "] found on type: " + type);
            builder = new AnnotatedTypeBuilder<X>().readFromType(type);
            builder.addToClass(SecurityInterceptorBindingLiteral.INSTANCE);
            isSecured = true;
         }
      }
      
      if (!isSecured)
      {
         for (AnnotatedMethod<? super X> m : type.getMethods())
         {
            if (m.isAnnotationPresent(Secures.class)) continue;
            
            for (final Annotation annotation : m.getAnnotations())
            {
               if (annotation.annotationType().isAnnotationPresent(SecurityBindingType.class))
               {
                  System.out.println("Security binding [" + annotation + "] found on method: " + m);
                  if (builder == null)
                  {
                     builder = new AnnotatedTypeBuilder<X>().readFromType(type);
                     builder.addToMethod(m, SecurityInterceptorBindingLiteral.INSTANCE);
                  }                  
               }
            }
         }         
      }
      
      if (builder != null)
      {
         event.setAnnotatedType(builder.create());
      }
      
   }
}
