package org.jboss.seam.security;

import javax.enterprise.util.AnnotationLiteral;



/**
 * @author Shane Bryzak
 */
class SecurityInterceptorBindingLiteral extends AnnotationLiteral<SecurityInterceptorBinding> {
    private static final long serialVersionUID = 2189092542638784524L;

    static SecurityInterceptorBindingLiteral INSTANCE = new SecurityInterceptorBindingLiteral();
}
