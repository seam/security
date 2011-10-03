package org.jboss.seam.security.external.openid;

import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jboss.solder.logging.Logger;
import org.jboss.seam.security.external.InvalidRequestException;
import org.jboss.seam.security.external.ResponseHandler;

/**
 * @author Marcel Kolsteren
 */
public class OpenIdServlet extends HttpServlet {
    private static final long serialVersionUID = -3058316157797375740L;

    // TODO: use injection as soon as Jira issue SOLDER-63 has been solved
    // @Inject
    private Logger log = Logger.getLogger(OpenIdServlet.class);

    @Inject
    private ResponseHandler responseHandler;

    @Inject
    private OpenIdProviderAuthenticationService openIdProviderAuthenticationService;

    @Inject
    private OpenIdRpAuthenticationService openIdRpAuthenticationService;

    @Inject
    private Instance<OpenIdRpBeanApi> rpBean;

    @Inject
    private Instance<OpenIdProviderBeanApi> opBean;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        doGetOrPost(request, response);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        doGetOrPost(request, response);
    }

    private void doGetOrPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            handleMessage(request, response);
        } catch (InvalidRequestException e) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, e.getDescription());
            log.infof("Bad request received from %s: %s", request.getRemoteHost(), e.getDescription());
        }
    }

    private void handleMessage(HttpServletRequest httpRequest, HttpServletResponse response) throws InvalidRequestException {
        Matcher matcher = Pattern.compile("/(OP|RP)/([^/]*?)$").matcher(httpRequest.getRequestURI());
        boolean found = matcher.find();
        if (!found) {
            responseHandler.sendError(HttpServletResponse.SC_NOT_FOUND, "No service endpoint exists for this URL.", response);
            return;
        }
        OpenIdProviderOrRelyingParty opOrRp = OpenIdProviderOrRelyingParty.valueOf(matcher.group(1));
        OpenIdService service = OpenIdService.getByName(matcher.group(2));

        if (service == null) {
            responseHandler.sendError(HttpServletResponse.SC_NOT_FOUND, "No service endpoint exists for this URL.", response);
            return;
        }

        switch (service) {
            case OPEN_ID_SERVICE:
                if (opOrRp == OpenIdProviderOrRelyingParty.OP) {
                    openIdProviderAuthenticationService.handleIncomingMessage(httpRequest, response);
                } else {
                    openIdRpAuthenticationService.handleIncomingMessage(httpRequest, response);
                }
                break;
            case XRDS_SERVICE:
                if (opOrRp == OpenIdProviderOrRelyingParty.OP) {
                    opBean.get().writeOpIdentifierXrds(responseHandler.getWriter("application/xrds+xml", response));
                } else {
                    rpBean.get().writeRpXrds(responseHandler.getWriter("application/xrds+xml", response));
                }
                break;
            default:
                throw new RuntimeException("Unsupported service " + service);
        }
    }

    public void destroy() {
    }
}
