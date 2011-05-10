package org.jboss.seam.security;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import javax.enterprise.context.NormalScope;

import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

/**
 * A scope that is active during the authentication process
 *
 * @author Shane Bryzak
 */
@Documented
@Retention(RUNTIME)
@Target({TYPE, METHOD, FIELD})
@NormalScope(passivating = false)
public @interface AuthenticationScoped {

}
