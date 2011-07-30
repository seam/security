package org.jboss.seam.security.external.openid;

import java.io.Serializable;

import javax.enterprise.context.SessionScoped;
import javax.inject.Inject;
import javax.inject.Named;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

import org.jboss.seam.security.Authenticator;

/**
 * Essentially the same as OpenIdAuthenticator, however the URL that the user is redirected to
 * is captured in a mock object, and then made available as a property of this Authenticator
 * to allow an AJAX-based client to perform specialized handling.
 * 
 * @author Shane Bryzak
 *
 */
public 
@Named("openIdAjaxAuthenticator")
@SessionScoped
class OpenIdAjaxAuthenticator extends OpenIdAuthenticator implements Authenticator, Serializable {
    private static final long serialVersionUID = 7737243244817530552L;
    
    @Inject private HttpServletResponse httpResponse;
    
    private MockResponse mockResponse;
    
    private String redirectUrl;
    
    private class MockResponse extends HttpServletResponseWrapper {
        
        public MockResponse(HttpServletResponse response) {
            super(response);
        }

        private String redirectUrl;
        
        @Override
        public void sendRedirect(String url) {
            this.redirectUrl = url;
        }
        
        public String getRedirectUrl() {
            return redirectUrl;
        }
    }
    
    public void authenticate() {
        this.mockResponse = new MockResponse(httpResponse);
        super.authenticate();
        this.redirectUrl = mockResponse.getRedirectUrl();
    }
    
    @Override 
    public HttpServletResponse getResponse() {
        return this.mockResponse;
    }
    
    public String getRedirectUrl() {
        return this.redirectUrl;
    }

}
