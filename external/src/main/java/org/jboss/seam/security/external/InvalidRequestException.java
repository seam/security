package org.jboss.seam.security.external;

/**
 * @author Marcel Kolsteren
 */
public class InvalidRequestException extends Exception {
    private static final long serialVersionUID = -9127592026257210986L;

    private String description;

    private Exception cause;

    public InvalidRequestException(String description) {
        this(description, null);
    }

    public InvalidRequestException(String description, Exception cause) {
        super();
        this.description = description;
        this.cause = cause;
    }

    public String getDescription() {
        return description;
    }

    public Exception getCause() {
        return cause;
    }

    public void setCause(Exception cause) {
        this.cause = cause;
    }
}
