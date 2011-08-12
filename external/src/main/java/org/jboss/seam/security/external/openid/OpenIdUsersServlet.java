package org.jboss.seam.security.external.openid;

import java.io.IOException;
import java.net.URLDecoder;

import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.security.external.spi.OpenIdProviderSpi;

/**
 * @author Marcel Kolsteren
 */
public class OpenIdUsersServlet extends HttpServlet {
    private static final long serialVersionUID = 1476698956314628568L;

    @Inject
    private Instance<OpenIdProviderBeanApi> opBean;

    @Inject
    private Instance<OpenIdProviderSpi> providerSpi;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String prefix = opBean.get().getUsersUrlPrefix();
        if (!request.getRequestURL().toString().startsWith(prefix)) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "Only accepting requests for URLs starting with " + prefix);
            return;
        }

        String userNamePart = request.getRequestURL().substring(prefix.length());
        String userName = URLDecoder.decode(userNamePart, "UTF-8");

        if (providerSpi.get().userExists(userName)) {
            response.setContentType("application/xrds+xml");
            opBean.get().writeClaimedIdentifierXrds(response.getWriter(), opBean.get().getOpLocalIdentifierForUserName(userName));
        } else {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "User " + userName + " does not exist.");
        }
    }
}
