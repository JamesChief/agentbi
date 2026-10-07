// 订阅框提交。首页和榜单页共用：文案从 window.__SUB_L 取（各自注入）。
// 不收集 IP 之外的任何东西——表单里就一个邮箱字段。
(function () {
  const L = window.__SUB_L || {};
  const T = k => L[k] !== undefined ? L[k] : k;

  document.querySelectorAll('.subscribe-form').forEach(form => {
    const box = form.closest('.subscribe');
    const msg = box && box.querySelector('.subscribe-msg');
    const input = form.querySelector('.subscribe-email');

    form.addEventListener('submit', async e => {
      e.preventDefault();
      if (!msg) return;
      const email = (input && input.value || '').trim();
      if (!email) { msg.textContent = T('sub.err_invalid'); return; }
      msg.textContent = '…';

      // src 只用来区分长版/短版哪个转化好，不入文案
      const src = box && box.classList.contains('subscribe-long') ? 'long' : 'short';
      const lang = document.documentElement.lang || 'en';
      try {
        const res = await fetch('/api/subscribe?src=' + src + '&lang=' + encodeURIComponent(lang), {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({email: email})
        });
        const j = await res.json();
        msg.textContent = j.ok ? j.msg : (j.error || T('sub.err_fail'));
        if (j.ok && input) input.value = '';
      } catch (err) {
        msg.textContent = T('sub.err_fail');
      }
    });
  });
})();
