package org.jboss.seam.security.external.dialogues;

import java.io.IOException;

import javax.inject.Inject;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.security.external.dialogues.api.DialogueManager;

@WebFilter(filterName = "DialogueFilter", urlPatterns = "/*")
public class DialogueFilter implements Filter
{
   public final static String DIALOGUE_ID_PARAM = "dialogueId";

   @Inject
   private DialogueManager manager;

   public void init(FilterConfig filterConfig) throws ServletException
   {
   }

   public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException
   {
      if (manager.isAttached())
      {
         manager.detachDialogue();
      }

      String dialogueId = request.getParameter(DIALOGUE_ID_PARAM);

      if (dialogueId != null)
      {
         if (!manager.isExistingDialogue(dialogueId))
         {
            ((HttpServletResponse) response).sendError(HttpServletResponse.SC_BAD_REQUEST, "dialogue " + dialogueId + " does not exist");
            return;
         }
         manager.attachDialogue(dialogueId);
      }

      chain.doFilter(request, response);

      if (manager.isAttached())
      {
         manager.detachDialogue();
      }
   }

   public void destroy()
   {
   }
}
