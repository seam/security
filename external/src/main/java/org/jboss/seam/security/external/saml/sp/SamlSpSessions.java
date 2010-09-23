/*
 * JBoss, Home of Professional Open Source
 * Copyright 2010, Red Hat, Inc., and individual contributors
 * by the @authors tag. See the copyright.txt in the distribution for a
 * full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.jboss.seam.security.external.saml.sp;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

import javax.enterprise.context.SessionScoped;

import org.jboss.seam.security.external.saml.api.SamlPrincipal;
import org.jboss.seam.security.external.saml.api.SamlSpSession;

/**
 * @author Marcel Kolsteren
 * 
 */
@SessionScoped
public class SamlSpSessions implements Serializable
{
   private static final long serialVersionUID = 6297278286428111620L;

   private Set<SamlSpSessionImpl> sessions = new HashSet<SamlSpSessionImpl>();

   public void addSession(SamlSpSessionImpl session)
   {
      sessions.add(session);
   }

   public void removeSession(SamlSpSessionImpl session)
   {
      sessions.remove(session);
   }

   public Set<SamlSpSessionImpl> getSessions()
   {
      return sessions;
   }

   public SamlSpSession getSession(SamlPrincipal samlPrincipal, String idpEntityId, String sessionIndex)
   {
      for (SamlSpSessionImpl session : sessions)
      {
         if (session.getPrincipal().equals(samlPrincipal) && session.getIdentityProvider().getEntityId().equals(idpEntityId) && session.getSessionIndex().equals(sessionIndex))
         {
            return session;
         }
      }
      return null;
   }
}
