# TASK_QUEUE

- Extract host-collection logic from the existing ZIP artifact into source-controlled collectors.
- Expand rules to cover scheduled tasks, WMI event subscriptions, browser helper objects, and COM hijacks.
- Add signed-publisher allowlists and hash-based suppression for known benign autoruns.
- Publish CI to run unit tests and package linting on every push.
