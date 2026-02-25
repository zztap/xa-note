(function () {
  const path = window.location.pathname;
  const shareMatch = path.match(/^\/share\/([a-zA-Z0-9_-]+)$/);

  if (shareMatch) {
    const shareCode = shareMatch[1];
    console.log('📤 Share page detected:', shareCode);

    // 1. 致命打击：拦截对 root 的访问，让 React "Target container is not a DOM element" 初始化失败而不干扰我们的网络请求
    const originalGetElementById = document.getElementById;
    document.getElementById = function (id) {
      if (id === 'root') return null;
      return originalGetElementById.call(document, id);
    };

    // 2. 只有等 DOM（body）解析出来了，才能安全往里面塞东西
    document.addEventListener('DOMContentLoaded', () => {
      // 清理原始界面的加载态和废弃容器
      const loader = document.querySelector('#loader-wrapper');
      if (loader) loader.remove();
      const originalRoot = document.querySelector('#root');
      if (originalRoot) originalRoot.remove();

      // 建立属于我们自己的绝对领域，避开广告拦截器拦截带有 share 关键词的 ID
      const container = document.createElement('div');
      container.id = 'xa-note-view-root';
      document.body.appendChild(container);

      container.innerHTML = `
                <div style="min-height: 100vh; display: flex; align-items: center; justify-content: center; font-family: system-ui, -apple-system, sans-serif;">
                  <div style="text-align: center;">
                    <div style="font-size: 2rem; margin-bottom: 1rem;">📝</div>
                    <div style="color: #666;">Loading shared note...</div>
                  </div>
                </div>
            `;

      // 去拉取数据
      fetch(`/api/share/${shareCode}/view`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      })
        .then(res => {
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
          return res.json();
        })
        .then(note => {
          container.innerHTML = `
                <div style="min-height: 100vh; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 2rem;">
                  <div style="max-width: 800px; margin: 0 auto; background: white; border-radius: 16px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); overflow: hidden;">
                    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 2rem; color: white;">
                      <h1 style="margin: 0; font-size: 2rem; font-weight: 600;">${note.title || 'Untitled Note'}</h1>
                      <div style="margin-top: 0.5rem; opacity: 0.9; font-size: 0.9rem;">
                        📤 Shared Note • Created: ${new Date(note.created_at).toLocaleDateString()}
                      </div>
                    </div>
                    <div style="padding: 2rem;">
                      <div id="note-content" style="line-height: 1.8; color: #333; font-size: 1rem;"></div>
                    </div>
                    <div style="padding: 1.5rem 2rem; background: #f8f9fa; border-top: 1px solid #e9ecef; text-align: center; color: #666; font-size: 0.875rem;">
                      Powered by <strong>XA Note</strong>
                    </div>
                  </div>
                </div>
                `;

          // 简单的 Markdown -> HTML
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
              .replace(/\`([^\`]+)\`/g, '<code style="background: #f1f3f5; padding: 0.2rem 0.4rem; border-radius: 4px; font-family: monospace; font-size: 0.9em;">$1</code>')
              .replace(/\n\n/g, '</p><p style="margin: 1rem 0;">')
              .replace(/\n/g, '<br>');
            contentDiv.innerHTML = '<p style="margin: 1rem 0;">' + html + '</p>';
          } else {
            contentDiv.innerHTML = '<p style="color: #999; font-style: italic;">This note is empty.</p>';
          }
        })
        .catch(error => {
          console.error('Failed to load shared note:', error);
          container.innerHTML = `
                <div style="min-height: 100vh; display: flex; align-items: center; justify-content: center; font-family: system-ui, -apple-system, sans-serif;">
                  <div style="text-align: center; max-width: 400px; padding: 2rem;">
                    <div style="font-size: 3rem; margin-bottom: 1rem;">❌</div>
                    <h2 style="margin: 0 0 0.5rem 0; color: #333;">Share Not Found</h2>
                    <p style="color: #666; margin: 0;">This shared note may have expired or been deleted.</p>
                  </div>
                </div>
                `;
        });
    });
  }
})();
