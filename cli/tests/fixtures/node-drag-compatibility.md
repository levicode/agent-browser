# Node drag completion

An observed-reference node drag preserves the original E2E gesture: move to source, press once, move through a midpoint to the destination, move to the destination again while held, then release once. The second destination move lets HTML5 drag-and-drop receive dragover before release; a successful mouse command alone does not prove the application's drop handler accepted the gesture.

Bare-point drag and timed swipe retain their original pointer sequence. Every move keeps the same exact page/operation authority and deadline. A failed or unknown move is not retried. Destination query revalidation, observed-reference identity, and mandatory handle/input cleanup are unchanged.
