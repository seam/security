package org.jboss.seam.security.management.picketlink;

import javax.persistence.EntityManager;

import org.picketlink.idm.common.exception.IdentityException;
import org.picketlink.idm.spi.store.IdentityStoreSession;

/**
 * JPA-specific implementation of IdentityStoreSession, based on an EntityManager.
 *
 * @author Shane Bryzak
 */
public class JpaIdentityStoreSessionImpl implements IdentityStoreSession {
    private EntityManager em;

    public JpaIdentityStoreSessionImpl(EntityManager em) {
        this.em = em;
    }

    public EntityManager getEntityManager() {
        return em;
    }

    public void clear() throws IdentityException {
        em.clear();
    }

    public void close() throws IdentityException {
        em.close();
    }

    public void commitTransaction() {
        em.getTransaction().commit();
    }

    public Object getSessionContext() throws IdentityException {
        return em;
    }

    public boolean isOpen() {
        return em.isOpen();
    }

    public boolean isTransactionActive() {
        return em.getTransaction().isActive();
    }

    public boolean isTransactionSupported() {
        return true;
    }

    public void rollbackTransaction() {
        em.getTransaction().rollback();
    }

    public void save() throws IdentityException {
        em.flush();
    }

    public void startTransaction() {
        em.getTransaction().begin();
    }

}
