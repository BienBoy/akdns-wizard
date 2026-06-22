# Curses/TUI Rendering Notes

This note records general lessons for terminal UIs that use curses-style
incremental rendering. It is not specific to AKDNS business logic.

## Failure Pattern

A terminal page can look correct when a large update happens, but still fail on
a smaller update that touches fewer rows.

Typical symptoms:

- Full expand, full refresh, or large list changes look correct.
- Expanding or inserting a small group of rows leaves stale background color or
  reverse-video attributes.
- Text cells are redrawn correctly, but blank cells keep old attributes.

This usually points to a rendering/incremental-refresh problem, not a data
problem.

## Root Cause

Curses implementations try to optimize terminal output. Depending on the
backend and terminal, they may:

- Reuse existing cells instead of repainting blank cells.
- Use line insert/delete/move optimizations when list height changes.
- Treat blank cells and text cells differently in the generated terminal
  update.
- Preserve stale attributes in cells that the application assumes were cleared.

The bug may be hidden when a large update happens because enough rows are
rewritten to cover the stale cells. Smaller updates are often better at exposing
the problem.

## Practical Fixes

Use explicit, deterministic repainting for list rows:

- Clear each row with the exact attribute that row should have before writing
  text.
- If `hline()` or a long padded `addstr()` is unreliable on the target backend,
  fill the row cell-by-cell with `addch()`.
- Mark changed rows dirty with `touchline()` after writing them.
- Disable insert/delete-line optimizations for pages where rows are frequently
  inserted or removed: `idlok(False)`, `idcok(False)`, and `scrollok(False)`.
- When the visible structure changes, mark the affected list area damaged with
  `redrawln(top, row_count)` and repaint that area, instead of forcing a whole
  screen refresh on every cursor move.

Avoid using whole-screen clearing as the first solution. It can hide stale-cell
bugs but often causes visible flicker. Prefer targeted redraw of the affected
region.

## Debugging Guidance

When diagnosing a TUI repaint bug:

1. Compare small structural changes with large structural changes.
2. Check whether only blank cells are wrong.
3. Verify whether the issue disappears with a full-screen refresh.
4. If a full refresh fixes it, reduce the fix to the smallest damaged region.
5. Test on the actual terminal/backend where the bug was reported.

Do not assume a rendering path is correct just because a full redraw or large
update looks correct.

## Example From This Repository

The AKDNS wizard once had a region-selection page where:

- Pressing `O` to expand all groups rendered correctly.
- Pressing `o` to expand a small group such as Southeast Asia or Oceania left
  stale reverse-video background in blank cells below the selected row.
- Expanding Europe looked correct because it inserted many more rows and
  happened to overwrite enough of the affected area.

The effective fix was:

- Use `fill_curses_row()` to clear each row cell-by-cell with explicit
  attributes.
- Disable curses line insertion/deletion optimizations on that page.
- Use `redrawln()` for the list area when the visible list structure changes.
- Keep ordinary cursor movement incremental to avoid flicker.

The important lesson is not specific to regions or AKDNS: large updates can
mask stale terminal attributes, while small row insertions expose them.
