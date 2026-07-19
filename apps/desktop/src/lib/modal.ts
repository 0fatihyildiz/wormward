import type { Action } from "svelte/action";

/**
 * Accessible dialog behavior for a modal element: moves focus into the dialog on
 * open, traps Tab within it, closes on Escape, and restores focus to the trigger
 * on close. `use:dialog={() => (open = false)}` on the `.modal` element.
 */
export const dialog: Action<HTMLElement, () => void> = (node, close) => {
  let onClose = close ?? (() => {});
  const prev = document.activeElement as HTMLElement | null;
  const backdrop = node.parentElement;

  const focusable = () =>
    Array.from(
      node.querySelectorAll<HTMLElement>(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
      )
    ).filter((el) => !el.hasAttribute("disabled"));

  // Focus the first control (Cancel comes first in the DOM), else the dialog.
  (focusable()[0] ?? node).focus();

  function onKey(e: KeyboardEvent) {
    if (e.key === "Escape") {
      e.preventDefault();
      onClose();
      return;
    }
    if (e.key === "Tab") {
      const f = focusable();
      if (f.length === 0) return;
      const first = f[0];
      const last = f[f.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    }
  }

  // Click on the backdrop (outside the dialog) dismisses — handled here rather than
  // via a template onclick so the backdrop stays a plain, lint-clean element.
  function onBackdrop(e: MouseEvent) {
    if (e.target === backdrop) onClose();
  }

  node.addEventListener("keydown", onKey);
  backdrop?.addEventListener("click", onBackdrop);

  return {
    update(next: () => void) {
      onClose = next ?? onClose;
    },
    destroy() {
      node.removeEventListener("keydown", onKey);
      backdrop?.removeEventListener("click", onBackdrop);
      prev?.focus?.();
    },
  };
};
