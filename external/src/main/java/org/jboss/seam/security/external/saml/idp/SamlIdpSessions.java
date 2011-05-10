package org.jboss.seam.security.external.saml.idp;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

import javax.enterprise.context.SessionScoped;

import org.jboss.seam.security.external.saml.api.SamlIdpSession;
import org.jboss.seam.security.external.saml.api.SamlPrincipal;

/**
 * @author Marcel Kolsteren
 */
@SessionScoped
public class SamlIdpSessions implements Serializable {
    private static final long serialVersionUID = 6297278286428111620L;

    private Set<SamlIdpSessionImpl> sessions = new HashSet<SamlIdpSessionImpl>();

    public SamlIdpSession addSession(SamlPrincipal principal) {
        String sessionIndex;
        int i = 0;
        do {
            sessionIndex = Integer.toString(i);
        }
        while (getSession(principal, sessionIndex) != null);

        SamlIdpSessionImpl session = new SamlIdpSessionImpl();
        session.setPrincipal(principal);
        session.setSessionIndex(sessionIndex);
        sessions.add(session);

        return session;
    }

    public SamlIdpSession getSession(SamlPrincipal principal, String sessionIndex) {
        for (SamlIdpSessionImpl session : sessions) {
            if (session.getPrincipal().equals(principal) && session.getSessionIndex().equals(sessionIndex)) {
                return session;
            }
        }
        return null;
    }

    public void removeSession(SamlIdpSessionImpl session) {
        sessions.remove(session);
    }

    public Set<SamlIdpSessionImpl> getSessions() {
        return sessions;
    }
}
