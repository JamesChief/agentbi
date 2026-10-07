// 订阅框提交。目前只挂在榜单页（首页放过一版，挡检测流程，已撤）。
// 文案从 window.__SUB_L 取，由 serve.py 的 sub_script() 注入。
// 不收集邮箱以外的任何东西——表单里就一个字段。
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

      const lang = document.documentElement.lang || 'en';
      try {
        const res = await fetch('/api/subscribe?lang=' + encodeURIComponent(lang), {
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
