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

  document.querySelectorAll("[data-select-row]").forEach((row) => {
    const checkbox = row.querySelector("input[type='checkbox']");
    if (!checkbox) {
      return;
    }
    function syncSelectedClass() {
      row.classList.toggle("selected", checkbox.checked);
    }
    row.addEventListener("click", (event) => {
      if (event.target === checkbox) {
        syncSelectedClass();
        return;
      }
      checkbox.checked = !checkbox.checked;
      syncSelectedClass();
    });
    checkbox.addEventListener("change", syncSelectedClass);
    syncSelectedClass();
  });

  document.querySelectorAll("[data-choice-row]").forEach((row) => {
    const choices = row.querySelectorAll("input[type='radio']");
    if (!choices.length) {
      return;
    }
    function syncSelectedClass() {
      row.classList.toggle("selected", Array.from(choices).some((choice) => choice.checked));
    }
    choices.forEach((choice) => {
      choice.addEventListener("change", syncSelectedClass);
    });
    syncSelectedClass();
  });
})();
