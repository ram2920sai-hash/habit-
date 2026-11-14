/* NEXO installation controls: visible action + native prompt where available. */
(() => {
  let deferredPrompt = null;
  const isInstalled = () => window.matchMedia('(display-mode: standalone)').matches || navigator.standalone === true;
  const isIOS = () => /iPhone|iPad|iPod/i.test(navigator.userAgent);
  const isSecure = () => location.protocol === 'https:' || ['localhost', '127.0.0.1'].includes(location.hostname);
  const buttons = () => [...document.querySelectorAll('[data-install-nexo]')];
  function syncButtons() {
    buttons().forEach(button => {
      button.hidden = isInstalled();
      button.textContent = '⬇ Install NEXO';
    });
  }
  if ('serviceWorker' in navigator && isSecure()) {
    navigator.serviceWorker.register('/service-worker.js').catch(error => console.warn('NEXO SW:', error));
  }
  function showInstructions() {
    document.getElementById('nexo-install-help')?.remove();
    const overlay = document.createElement('div');
    overlay.id = 'nexo-install-help';
    overlay.className = 'nexo-install-overlay';
    overlay.setAttribute('role', 'presentation');
    const panel = document.createElement('section');
    panel.className = 'nexo-install-dialog';
    panel.setAttribute('role', 'dialog');
    panel.setAttribute('aria-modal', 'true');
    panel.setAttribute('aria-labelledby', 'nexo-install-title');
    const heading = document.createElement('h2');
    heading.id = 'nexo-install-title';
    heading.textContent = 'Install NEXO on your device';
    const intro = document.createElement('p');
    intro.textContent = 'Get a NEXO icon on your home screen or desktop, and open it like an app.';
    const steps = document.createElement('div');
    steps.className = 'nexo-install-steps';
    const items = isIOS()
      ? [['iPhone / iPad', 'Open this site in Safari, tap Share (square with arrow), then Add to Home Screen → Add.']]
      : [['Android', 'Open this site in Chrome, tap the three-dot menu, then Install app or Add to Home screen.'], ['Windows / Mac', 'Open this site in Chrome or Edge, then use the Install app option in the address bar or browser menu.']];
    if (!isSecure()) items.unshift(['Online hosting required', 'Use the HTTPS URL of your deployed NEXO app. GitHub Pages alone cannot run the Python backend.']);
    for (const [title, detail] of items) {
      const item = document.createElement('div');
      const name = document.createElement('strong');
      name.textContent = title;
      const description = document.createElement('p');
      description.textContent = detail;
      item.append(name, description);
      steps.append(item);
    }
    const note = document.createElement('p');
    note.className = 'nexo-install-note';
    note.textContent = 'If the install option is missing, check that you are using a supported browser and a secure HTTPS site. Installation does not make habit syncing work offline.';
    const close = document.createElement('button');
    close.type = 'button';
    close.className = 'primary';
    close.textContent = 'Got it';
    const dismiss = () => {overlay.remove(); document.removeEventListener('keydown', onEscape);};
    const onEscape = event => {if (event.key === 'Escape') dismiss();};
    close.addEventListener('click', dismiss);
    overlay.addEventListener('click', event => {if(event.target === overlay) dismiss();});
    document.addEventListener('keydown', onEscape);
    panel.append(heading, intro, steps, note, close);
    overlay.append(panel);
    document.body.append(overlay);
    close.focus();
  }
  window.addEventListener('beforeinstallprompt', event => {
    event.preventDefault();
    deferredPrompt = event;
    syncButtons();
  });
  document.addEventListener('click', async event => {
    const button = event.target.closest('[data-install-nexo]');
    if (!button) return;
    if (isInstalled()) return;
    if (deferredPrompt) {
      const prompt = deferredPrompt;
      deferredPrompt = null;
      try {
        await prompt.prompt();
        const choice = await prompt.userChoice;
        if (choice?.outcome === 'dismissed') showInstructions();
      } catch (error) { console.warn('Install prompt unavailable:', error); showInstructions(); }
    } else showInstructions();
  });
  window.addEventListener('appinstalled', () => {deferredPrompt = null; syncButtons(); document.getElementById('nexo-install-help')?.remove();});
  syncButtons();
})();
