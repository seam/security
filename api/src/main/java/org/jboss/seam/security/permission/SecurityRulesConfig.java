package org.jboss.seam.security.permission;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import javax.inject.Qualifier;

import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.PARAMETER;
import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

/**
 * This qualifier is used solely for the configuration of a DroolsConfig using
 * the Seam XML config module
 *
 * @author Shane Bryzak
 */
@Qualifier
@Target({TYPE, METHOD, FIELD, PARAMETER})
@Documented
@Retention(RUNTIME)
public @interface SecurityRulesConfig {

}
