package org.jboss.seam.security.extension;

import java.io.Serializable;
import java.lang.reflect.Method;
import java.lang.reflect.Type;

import javax.enterprise.inject.spi.BeanManager;
import javax.inject.Inject;
import javax.interceptor.AroundInvoke;
import javax.interceptor.Interceptor;
import javax.interceptor.InvocationContext;

import org.jboss.seam.security.Identity;
import org.jboss.seam.security.extension.SecurityExtension.Authorizer;

/**
 * Provides authorization services for component invocations.
 * 
 * @author Shane Bryzak
 */
@SecurityInterceptorBinding @Interceptor
public class SecurityInterceptor implements Serializable
{
   private static final long serialVersionUID = -6567750187000766925L;
   
   @Inject BeanManager manager;
   @Inject Identity identity;
   
   @Inject SecurityExtension extension;
   
   @AroundInvoke
   public Object aroundInvoke(InvocationContext invocation) throws Exception
   {
      System.out.println("SecurityInterceptor invoked");
      
      Method method = invocation.getMethod();
      
      for (Authorizer authorizer : extension.lookupAuthorizerStack(method))
      {
         authorizer.authorize();
      }
      
      return invocation.proceed();
   }
}
