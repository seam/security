package org.jboss.seam.security;

import java.io.Serializable;
import java.lang.reflect.Method;

import javax.inject.Inject;
import javax.interceptor.AroundInvoke;
import javax.interceptor.Interceptor;
import javax.interceptor.InvocationContext;

import org.jboss.seam.security.SecurityExtension.Authorizer;

/**
 * Provides authorization services for component invocations.
 * 
 * @author Shane Bryzak
 * @author <a href="mailto:lincolnbaxter@gmail.com">Lincoln Baxter, III</a>
 */
@SecurityInterceptorBinding
@Interceptor
public class SecurityInterceptor implements Serializable {
    private static final long serialVersionUID = -6567750187000766925L;

    @Inject
    SecurityExtension extension;

    @AroundInvoke
    public Object aroundInvoke(InvocationContext invocation) throws Exception {
        Method method = invocation.getMethod();

        for (Authorizer authorizer : extension.lookupAuthorizerStack(method, invocation.getTarget().getClass())) {
            authorizer.authorize(invocation);
        }

        return invocation.proceed();
    }
}
