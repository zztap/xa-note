(function () {
  const path = window.location.pathname;
  const shareMatch = path.match(/^\/share\/([a-zA-Z0-9_-]+)$/);

  if (shareMatch) {
    const shareCode = shareMatch[1];
    console.log('📤 Share page detected:', shareCode);

    // 0. 极限优化：注入核弹级 CSS，彻底抹杀所有原本的 React UI 和加载动画，防止出现“加载中...”闪烁
    const style = document.createElement('style');
    style.innerHTML = `
      #root, #loader-wrapper { display: none !important; opacity: 0 !important; pointer-events: none !important; }
      body { background: #f8fafc; }
    `;
    document.documentElement.appendChild(style);

    // 1. 致命打击：毒化原生选取器，确保 React 的 createRoot 会因为找不到挂载点而静默奔溃
    const originalGetElementById = document.getElementById;
    document.getElementById = function (id) {
      if (id === 'root') return null;
      return originalGetElementById.call(document, id);
    };
    const originalQuerySelector = document.querySelector;
    document.querySelector = function (selector) {
      if (selector === '#root' || selector === '.root') return null;
      return originalQuerySelector.call(document, selector);
    };

    // 2. 🌟 零瀑布流预发射 (Zero-Waterfall Fetch)
    // 绝不等 DOMContentLoaded！也就是绝不等那几 MB 的 React JS 下载完！直接发请求拉取数据！
    const notePromise = fetch(`/api/share/${shareCode}/view`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    }).then(res => {
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    }).catch(error => {
      console.error('Failed to pre-fetch shared note:', error);
      return { _error: true };
    });

    // 3. 等浏览器把 <body> 准备好，我们就直接把数据拍上去，跳过所有等待
    document.addEventListener('DOMContentLoaded', () => {
      // 建立绝对领域
      const container = document.createElement('div');
      container.id = 'xa-note-view-root';
      document.body.appendChild(container);

      // 临时加载状态（如果接口极慢的情况下才会出现）
      container.innerHTML = `
        <div style="min-height: 100vh; display: flex; align-items: center; justify-content: center; font-family: system-ui, -apple-system, sans-serif;">
          <div style="text-align: center; animation: pulse 2s infinite;">
            <div style="font-size: 2.5rem; margin-bottom: 1rem;">📝</div>
            <div style="color: #6366f1; font-weight: 500;">提取笔记碎片中...</div>
          </div>
        </div>
      `;

      // 结算之前提前射出去的子弹 (Promise)
      notePromise.then(note => {
        if (note._error) {
          container.innerHTML = `
            <div style="min-height: 100vh; display: flex; align-items: center; justify-content: center; font-family: system-ui, -apple-system, sans-serif;">
              <div style="text-align: center; max-width: 400px; padding: 2rem;">
                <div style="font-size: 3rem; margin-bottom: 1rem;">❌</div>
                <h2 style="margin: 0 0 0.5rem 0; color: #333;">Share Not Found</h2>
                <p style="color: #666; margin: 0;">This shared note may have expired or been deleted.</p>
              </div>
            </div>
            `;
          return;
        }

        container.innerHTML = `
          <div style="min-height: 100vh; background: #f9fafb; padding: 2rem; font-family: 'Inter', system-ui, -apple-system, sans-serif;">
            <div style="max-width: 820px; margin: 0 auto; background: white; border-radius: 12px; border: 1px solid #e5e7eb; box-shadow: 0 4px 20px rgba(0,0,0,0.03); overflow: hidden;">
              <div style="padding: 2.5rem 2.5rem 1.5rem 2.5rem; border-bottom: 1px solid #f3f4f6; position: relative;">
                <!-- 侧边马卡龙装饰条 -->
                <div style="position: absolute; left: 0; top: 2.5rem; height: 2.5rem; width: 4px; background: #818cf8; border-radius: 0 4px 4px 0;"></div>
                <h1 style="margin: 0; font-size: 1.875rem; font-weight: 700; color: #111827; letter-spacing: -0.025em;">${note.title || 'Untitled Note'}</h1>
                <div style="margin-top: 0.75rem; color: #6b7280; font-size: 0.875rem; display: flex; align-items: center; gap: 0.5rem;">
                  <span style="background: #eff6ff; color: #3b82f6; padding: 2px 8px; border-radius: 4px; font-weight: 500; font-size: 0.75rem;">Shared Note</span>
                  <span style="color: #d1d5db;">•</span>
                  <span>Created: ${new Date(note.created_at).toLocaleDateString()}</span>
                </div>
              </div>
              <div style="padding: 2.5rem;">
                <div id="note-content" style="line-height: 1.8; color: #374151; font-size: 1.05rem;"></div>
              </div>
              <div style="padding: 1.5rem 2.5rem; background: #ffffff; border-top: 1px solid #f3f4f6; text-align: center; color: #9ca3af; font-size: 0.75rem; letter-spacing: 0.05em;">
                Powered by <strong style="color: #4b5563;">XA Note</strong>
              </div>
            </div>
          </div>
          `;

        const contentDiv = document.getElementById('note-content');
        if (note.content) {
          let html = note.content
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/^### (.*$)/gim, '<h3 style="margin-top: 1.5rem; margin-bottom: 0.75rem; font-size: 1.25rem; font-weight: 600;">$1</h3>')
            .replace(/^## (.*$)/gim, '<h2 style="margin-top: 2rem; margin-bottom: 1rem; font-size: 1.5rem; font-weight: 600;">$1</h2>')
            .replace(/^# (.*$)/gim, '<h1 style="margin-top: 2rem; margin-bottom: 1rem; font-size: 1.875rem; font-weight: 700;">$1</h1>')
            .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
            .replace(/\*([^*]+)\*/g, '<em>$1</em>')
            .replace(/\`([^\`]+)\`/g, '<code style="background: rgba(99, 102, 241, 0.1); color: #6366f1; padding: 0.2rem 0.4rem; border-radius: 4px; font-family: monospace; font-size: 0.9em;">$1</code>')
            .replace(/\n\n/g, '</p><p style="margin: 1rem 0;">')
            .replace(/\n/g, '<br>');
          contentDiv.innerHTML = '<p style="margin: 1rem 0;">' + html + '</p>';
        } else {
          contentDiv.innerHTML = '<p style="color: #999; font-style: italic;">This note is empty.</p>';
        }
      });
    });
  }
})();
