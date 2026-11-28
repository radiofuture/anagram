// The join page of the node (`/join`). The invite is in
// the fragment of the link, which the browser never sends to the server.
// This script gives the fragment to the app: "Open Anagram" becomes
// `anagram://join/<fragment>`. It also shows the full link, for a computer
// where the app does not open (the person pastes it in Anagram).
//
// Only base64url text is used. Other text leaves `anagram://open`.
(() => {
  const MAX = 8000; // the app refuses a link longer than 8192 characters
  const fragment = window.location.hash.slice(1);
  if (!/^[A-Za-z0-9_-]+$/.test(fragment) || fragment.length > MAX) return;
  const open = document.getElementById('join-open');
  if (open) open.setAttribute('href', `anagram://join/${fragment}`);
  const field = document.getElementById('join-link-field');
  const input = document.getElementById('join-link');
  if (field && input) {
    input.value = window.location.href;
    input.addEventListener('focus', () => input.select());
    field.hidden = false;
  }
})();
