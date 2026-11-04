// Corre en el mundo de la página: Gmail guarda en GLOBALS[9] el identificador
// de cuenta que pide la URL de "Mostrar original".
if (Array.isArray(window.GLOBALS) && typeof window.GLOBALS[9] === 'string') {
  document.documentElement.setAttribute('data-ev-ik', window.GLOBALS[9]);
}
