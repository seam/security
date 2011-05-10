package org.jboss.seam.security;

/**
 * Any exception that is raised by the security module extends from this runtime
 * exception class, making it easy for other modules and extensions to catch all
 * security-related exceptions in a single catch block, if need be.
 *
 * @author Dan Allen
 */
public abstract class SecurityException extends RuntimeException {
    private static final long serialVersionUID = 789326682407249952L;

    public SecurityException() {
        super();
    }

    public SecurityException(String message, Throwable cause) {
        super(message, cause);
    }

    public SecurityException(String message) {
        super(message);
    }

    public SecurityException(Throwable cause) {
        super(cause);
    }
}
