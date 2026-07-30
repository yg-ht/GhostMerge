(() => {
  let reviewInFlight = false;

  function isTypingTarget(element) {
    if (!element) {
      return false;
    }
    const tagName = element.tagName;
    return tagName === "TEXTAREA" || tagName === "INPUT" || tagName === "SELECT" || element.isContentEditable;
  }

  document.addEventListener("keydown", (event) => {
    if (event.repeat || reviewInFlight) {
      return;
    }
    const activeElement = document.activeElement;
    const enterOnRadio =
      event.key === "Enter" && activeElement instanceof HTMLInputElement && activeElement.type === "radio";
    if (isTypingTarget(activeElement) && event.key !== "Escape" && !enterOnRadio) {
      return;
    }
    if (
      activeElement instanceof HTMLButtonElement ||
      (activeElement instanceof HTMLAnchorElement && activeElement.hasAttribute("href"))
    ) {
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

  document.querySelectorAll("[data-decision-choice]").forEach((choice) => {
    const action = choice.dataset.decisionChoice;
    const decisionButton = Array.from(document.querySelectorAll("[data-decision-button]")).find(
      (button) => button.dataset.decisionButton === action,
    );
    if (!decisionButton) {
      return;
    }
    function applyDecision() {
      decisionButton.click();
    }
    choice.addEventListener("click", applyDecision);
    choice.addEventListener("keydown", (event) => {
      if (event.key !== "Enter" && event.key !== " ") {
        return;
      }
      event.preventDefault();
      event.stopPropagation();
      applyDecision();
    });
  });

  document.querySelectorAll("[data-choice-row]").forEach((row) => {
    const choices = row.querySelectorAll("input[type='radio']");
    const choiceCells = row.querySelectorAll("[data-choice-cell]");
    const clearButton = row.querySelector("[data-clear-choice]");
    if (!choices.length) {
      return;
    }
    function syncSelectedClass() {
      const selectedChoice = Array.from(choices).find((choice) => choice.checked);
      choiceCells.forEach((cell) => {
        cell.classList.toggle("selected-choice", Boolean(selectedChoice) && cell.dataset.choiceValue === selectedChoice.value);
      });
      if (clearButton) {
        clearButton.disabled = !selectedChoice;
      }
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
    if (clearButton) {
      clearButton.addEventListener("click", (event) => {
        event.stopPropagation();
        choices.forEach((choice) => {
          choice.checked = false;
        });
        syncSelectedClass();
      });
    }
    syncSelectedClass();
  });

  document.querySelectorAll("[data-review-form]").forEach((form) => {
    form.addEventListener("submit", (event) => {
      if (reviewInFlight || form.getAttribute("aria-busy") === "true") {
        event.preventDefault();
        return;
      }
      reviewInFlight = true;
      form.setAttribute("aria-busy", "true");
      const status = document.createElement("p");
      status.className = "review-busy-status";
      status.setAttribute("role", "status");
      status.textContent = form.dataset.busyMessage || "Working…";
      form.appendChild(status);
    });
  });

  window.addEventListener("pageshow", () => {
    reviewInFlight = false;
    document.querySelectorAll("[data-review-form][aria-busy='true']").forEach((form) => {
      form.removeAttribute("aria-busy");
      form.querySelectorAll(".review-busy-status").forEach((status) => status.remove());
    });
  });
})();
