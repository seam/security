package org.jboss.seam.security.external.api;

import javax.servlet.http.HttpServletResponse;

/**
 * This class is used in the SPI to pass the HTTP response on to the
 * application. It also contains methods that make it easier for the application
 * to propagate the dialogue over redirects or postbacks.
 *
 * @author Marcel Kolsteren
 */
public interface ResponseHolder {
    /**
     * Gets the HTTP servlet response
     *
     * @return the response
     */
    HttpServletResponse getResponse();

    /**
     * Results in a redirect to the specified URL. If a dialogue is active, the
     * id of that dialogue will be appended to the URL as a query parameter, so
     * that the dialogue will be restored when the browser gets the redirect URL.
     *
     * @param url URL
     */
    void redirectWithDialoguePropagation(String url);

    /**
     * Adds the id of the current dialogue to the URL. If no dialogue is active,
     * it just returns the URL unmodified.
     *
     * @param url URL
     * @return URL
     */
    String addDialogueIdToUrl(String url);
}
