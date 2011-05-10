package org.jboss.seam.security.external.dialogues;

import org.jboss.seam.security.external.dialogues.api.Dialogue;
import org.jboss.seam.security.external.dialogues.api.DialogueScoped;

@DialogueScoped
public class DialogueBean implements Dialogue {
    private String id;

    private boolean finished;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public boolean isFinished() {
        return finished;
    }

    public void setFinished(boolean finished) {
        this.finished = finished;
    }
}
