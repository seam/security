package org.jboss.seam.security.external.saml.sp;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

import javax.enterprise.context.SessionScoped;

import org.jboss.seam.security.external.saml.api.SamlPrincipal;
import org.jboss.seam.security.external.saml.api.SamlSpSession;

/**
 * @author Marcel Kolsteren
 */
@SessionScoped
public class SamlSpSessions implements Serializable {
    private static final long serialVersionUID = 6297278286428111620L;

    private Set<SamlSpSessionImpl> sessions = new HashSet<SamlSpSessionImpl>();

    public void addSession(SamlSpSessionImpl session) {
        sessions.add(session);
    }

    public void removeSession(SamlSpSessionImpl session) {
        sessions.remove(session);
    }

    public Set<SamlSpSessionImpl> getSessions() {
        return sessions;
    }

    public SamlSpSession getSession(SamlPrincipal samlPrincipal, String idpEntityId, String sessionIndex) {
        for (SamlSpSessionImpl session : sessions) {
            if (session.getPrincipal().equals(samlPrincipal) && session.getIdentityProvider().getEntityId().equals(idpEntityId) && session.getSessionIndex().equals(sessionIndex)) {
                return session;
            }
        }
        return null;
    }
}
