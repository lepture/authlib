(function() {
  function pageAd() {
    var h1 = document.querySelector('.t-body h1');
    if (!h1) return;

    var div = document.createElement('div');
    div.className = 'fund';
    var s = document.createElement('script');
    s.async = 1;
    s.id = '_carbonads_js';
    s.src = 'https://cdn.carbonads.com/carbon.js?serve=CE7DKK3W&placement=authliborg';
    div.appendChild(s);
    h1.parentNode.insertBefore(div, h1.nextSibling);
  }

  document.addEventListener('DOMContentLoaded', pageAd);
})();
