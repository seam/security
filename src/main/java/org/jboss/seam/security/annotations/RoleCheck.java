package org.jboss.seam.security.annotations;

import static java.lang.annotation.ElementType.ANNOTATION_TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Documented;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

/**
 * Meta-annotation that designates an annotation as being a role, 
 * requiring a security check prior to invoking the annotated method or class
 *
 * @author Shane Bryzak
 */
@Target({ANNOTATION_TYPE})
@Documented
@Retention(RUNTIME)
@Inherited
public @interface RoleCheck
{

}
