package org.jboss.seam.security;

/**
 * This exception is thrown when a security-related configuration error is detected,
 * such as a missing or ambiguous security binding type
 *
 * @author Shane Bryzak
 */
public class SecurityDefinitionException extends SecurityException {
    private static final long serialVersionUID = -5683365417825375411L;

    public SecurityDefinitionException(String message) {
        super(message);
    }

    public SecurityDefinitionException(Throwable cause) {
        super(cause);
    }

    public SecurityDefinitionException(String message, Throwable cause) {
        super(message, cause);
    }
}
