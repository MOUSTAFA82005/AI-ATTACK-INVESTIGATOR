"use strict";
// Show the missing address in the log line. textContent only, so a crafted URL stays plain text.
(function () {
  const slot = document.querySelector(".lost-path");
  if (slot) slot.textContent = (location.pathname + location.search).slice(0, 120);
})();
