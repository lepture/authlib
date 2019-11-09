(function() {
  function pageAd() {
    var h2 = document.querySelector('h2');
    if (!h2) return;

    var div = document.createElement('div');
    div.className = 'fund';
    div.id = 'codefund';
    var s = document.createElement('script');
    s.src = "https://app.codefund.io/properties/609/funder.js";
    if (Math.random() > 0.5) {
      s.src += '?template=horizontal';
    }
    s.async = 1;
    h2.parentNode.insertBefore(div, h2);
    document.head.appendChild(s);
  }

  document.addEventListener('DOMContentLoaded', pageAd);
})();
