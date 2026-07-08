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
    const choiceCells = row.querySelectorAll("[data-choice-cell]");
    if (!choices.length) {
      return;
    }
    function syncSelectedClass() {
      const selectedChoice = Array.from(choices).find((choice) => choice.checked);
      choiceCells.forEach((cell) => {
        cell.classList.toggle("selected-choice", Boolean(selectedChoice) && cell.dataset.choiceValue === selectedChoice.value);
      });
    }
    choices.forEach((choice) => {
      choice.addEventListener("change", syncSelectedClass);
    });
    choiceCells.forEach((cell) => {
      cell.addEventListener("click", (event) => {
        if (event.target instanceof HTMLInputElement && event.target.type === "radio") {
          syncSelectedClass();
          return;
        }
        const choice = row.querySelector(`input[type='radio'][value="${cell.dataset.choiceValue}"]`);
        if (!choice) {
          return;
        }
        choice.checked = true;
        choice.dispatchEvent(new Event("change", { bubbles: true }));
      });
    });
    syncSelectedClass();
  });
})();
