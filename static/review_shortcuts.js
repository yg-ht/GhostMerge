(() => {
  function isTypingTarget(element) {
    if (!element) {
      return false;
    }
    const tagName = element.tagName;
    return tagName === "TEXTAREA" || tagName === "INPUT" || tagName === "SELECT" || element.isContentEditable;
  }

  document.addEventListener("keydown", (event) => {
    if (isTypingTarget(document.activeElement) && event.key !== "Escape") {
      return;
    }
    if (event.key === "e") {
      const customField = document.querySelector("textarea[name='custom_value']");
      if (customField) {
        event.preventDefault();
        customField.focus();
      }
      return;
    }
    const escapedKey = window.CSS && CSS.escape ? CSS.escape(event.key) : event.key.replace(/"/g, '\\"');
    const button = document.querySelector(`[data-shortcut="${escapedKey}"]`);
    if (button) {
      event.preventDefault();
      button.click();
    }
  });
})();
