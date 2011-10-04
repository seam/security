package org.jboss.seam.security;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import javax.interceptor.InterceptorBinding;

/**
 * Interceptor binding type for SecurityInterceptor.  Users should not apply
 * this binding themselves, it is applied by the security portable extension.
 *
 * @author Shane Bryzak
 */
@Retention(RetentionPolicy.RUNTIME)
@InterceptorBinding
@Target({ElementType.TYPE, ElementType.METHOD})
        @interface SecurityInterceptorBinding {

}
