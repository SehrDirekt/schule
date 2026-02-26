document.addEventListener('DOMContentLoaded', () => {
  const panels = Array.from(document.querySelectorAll('.action-panel'));
  panels.forEach((panel) => {
    panel.addEventListener('toggle', () => {
      if (!panel.open) return;
      panels.forEach((other) => {
        if (other !== panel) {
          other.open = false;
        }
      });
    });
  });
});
