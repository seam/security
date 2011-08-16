package org.jboss.seam.security.external.dialogues;

import java.io.IOException;
import java.net.URLDecoder;

import javax.inject.Inject;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.security.external.dialogues.api.DialogueManager;

@WebFilter(filterName = "DialogueFilter", urlPatterns = "/openid/*")
public class DialogueFilter implements Filter {
    public final static String DIALOGUE_ID_PARAM = "dialogueId";

    @Inject
    private DialogueManager manager;

    public void init(FilterConfig filterConfig) throws ServletException {
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (manager.isAttached()) {
            manager.detachDialogue();
        }

        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        String queryString = httpServletRequest.getQueryString();

        // avoid calling getParameter() since it at this stage would break encoding setting
        if (queryString != null) {
            for (String param : queryString.split("&")) {
                if (param.startsWith(DIALOGUE_ID_PARAM) && param.length() > DIALOGUE_ID_PARAM.length() + 1) {
                    String dialogueId = URLDecoder.decode(param.substring(DIALOGUE_ID_PARAM.length() + 1), "utf-8");
                    if (dialogueId != null) {
                        if (!manager.isExistingDialogue(dialogueId)) {
                            ((HttpServletResponse) response).sendError(HttpServletResponse.SC_BAD_REQUEST, "dialogue " + dialogueId + " does not exist");
                            return;
                        }
                        manager.attachDialogue(dialogueId);
                    }
                    break;
                }
            }
        }


        chain.doFilter(request, response);

        if (manager.isAttached()) {
            manager.detachDialogue();
        }
    }

    public void destroy() {
    }
}
