(function() {
  function carbon() {
    var h1 = document.querySelector('.t-body h1');
    if (!h1) return;

    var div = document.createElement('div');
    div.className = 'fund';
    h1.parentNode.insertBefore(div, h1.nextSibling);

    var s = document.createElement('script');
    s.async = 1;
    s.id = '_carbonads_js';
    s.src = 'https://cdn.carbonads.com/carbon.js?serve=CE7DKK3W&placement=authliborg';
    div.appendChild(s);
  }

  function bsa() {
    var pagination = document.querySelector('.t-pagination');
    if (!pagination) return;
    var div = document.createElement('div');
    div.id = 'bsa';
    pagination.parentNode.insertBefore(div, pagination);

    var s = document.createElement('script');
    s.async = 1;
    s.src = 'https://m.servedby-buysellads.com/monetization.js';
    s.onload = function() {
      if(typeof window._bsa !== 'undefined' && window._bsa) {
        _bsa.init('custom', 'CE7DKK3M', 'placement:authliborg', { target: '#bsa', template: `
  <a href="##link##" class="native-box">
    <div class="native-sponsor">Sponsor</div>
    <div class="native-text"><strong>##company##</strong> - ##description##</div>
  </a>`}
        );
      }
    }
    document.body.appendChild(s);
  }

  document.addEventListener('DOMContentLoaded', function() {
    carbon();
    bsa();
  });
})();
