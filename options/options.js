const EV = globalThis.EmailVerifier;
const textarea = document.getElementById('brands');
const status = document.getElementById('status');

chrome.storage.sync.get({ brandsText: EV.DEFAULT_BRANDS_TEXT }).then((stored) => {
  textarea.value = stored.brandsText;
});

async function save() {
  try {
    await chrome.storage.sync.set({ brandsText: textarea.value });
    const lines = textarea.value.split('\n').filter((line) => line.trim()).length;
    const valid = EV.parseBrands(textarea.value).length;
    status.textContent = lines === valid
      ? `Guardado: ${valid} empresas.`
      : `Guardado: ${valid} empresas válidas; ${lines - valid} líneas ignoradas por formato.`;
  } catch (error) {
    status.textContent = `No se pudo guardar: ${error.message}`;
  }
}

document.getElementById('save').addEventListener('click', save);
document.getElementById('reset').addEventListener('click', () => {
  textarea.value = EV.DEFAULT_BRANDS_TEXT;
  save();
});
