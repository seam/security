package org.jboss.seam.security.annotations;

import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Documented;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

/**
 * Indicates that the action method requires the user to be a member of the 'admin' role to invoke.
 * 
 * @author Shane Bryzak
 */
@Target({TYPE, METHOD})
@Documented
@Retention(RUNTIME)
@Inherited
@RoleCheck
public @interface Admin
{

}
