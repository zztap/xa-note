(function () {
    const path = window.location.pathname;
    const shareMatch = path.match(/^\/share\/([a-zA-Z0-9_-]+)$/);

    if (shareMatch) {
        const shareCode = shareMatch[1];
        console.log('📤 Share page detected:', shareCode);

        // Prevent React app from loading
        const root = document.getElementById('root');
        root.innerHTML = '<div id="share-container"></div>';

        // Fetch and render shared note
        (async function loadSharedNote() {
            const container = document.getElementById('share-container');

            // Show loading state
            container.innerHTML = \
        <div style="min-height: 100vh; display: flex; align-items: center; justify-content: center; font-family: system-ui, -apple-system, sans-serif;">
          <div style="text-align: center;">
            <div style="font-size: 2rem; margin-bottom: 1rem;">📝</div>
            <div style="color: #666;">Loading shared note...</div>
          </div>
        </div>
      \;

            try {
                // Fetch shared note
                const response = await fetch(\/api/share/\/view\, {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({})
                });
        
                if (!response.ok) {
                  throw new Error(\HTTP \\);
                }
        
                const note = await response.json();
        
                // Render shared note
                container.innerHTML = \
                <div style="min-height: 100vh; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 2rem;">
                  <div style="max-width: 800px; margin: 0 auto; background: white; border-radius: 16px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); overflow: hidden;">
                    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 2rem; color: white;">
                      <h1 style="margin: 0; font-size: 2rem; font-weight: 600;">\</h1>
                      <div style="margin-top: 0.5rem; opacity: 0.9; font-size: 0.9rem;">
                        📤 Shared Note • Created: \
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
                \;
        
                // Render markdown content
                const contentDiv = document.getElementById('note-content');
                if (note.content) {
                  // Simple markdown-to-HTML conversion
                  let html = note.content
                    .replace(/&/g, '&amp;')
                    .replace(/</g, '&lt;')
                    .replace(/>/g, '&gt;')
                    .replace(/^### (.*$)/gim, '<h3 style="margin-top: 1.5rem; margin-bottom: 0.75rem; font-size: 1.25rem; font-weight: 600;"></h3>')
                    .replace(/^## (.*$)/gim, '<h2 style="margin-top: 2rem; margin-bottom: 1rem; font-size: 1.5rem; font-weight: 600;"></h2>')
                    .replace(/^# (.*$)/gim, '<h1 style="margin-top: 2rem; margin-bottom: 1rem; font-size: 1.875rem; font-weight: 700;"></h1>')
                    .replace(/\*\*([^*]+)\*\*/g, '<strong></strong>')
                    .replace(/\*([^*]+)\*/g, '<em></em>')
                    .replace(/\([^\]+)\/g, '<code style="background: #f1f3f5; padding: 0.2rem 0.4rem; border-radius: 4px; font-family: monospace; font-size: 0.9em;"></code>')
                    .replace(/\n\n/g, '</p><p style="margin: 1rem 0;">')
                    .replace(/\n/g, '<br>');
                  
                  contentDiv.innerHTML = '<p style="margin: 1rem 0;">' + html + '</p>';
                } else {
                  contentDiv.innerHTML = '<p style="color: #999; font-style: italic;">This note is empty.</p>';
                }
        
            } catch (error) {
                console.error('Failed to load shared note:', error);
                container.innerHTML = \
                <div style="min-height: 100vh; display: flex; align-items: center; justify-content: center; font-family: system-ui, -apple-system, sans-serif;">
                  <div style="text-align: center; max-width: 400px; padding: 2rem;">
                    <div style="font-size: 3rem; margin-bottom: 1rem;">❌</div>
                    <h2 style="margin: 0 0 0.5rem 0; color: #333;">Share Not Found</h2>
                    <p style="color: #666; margin: 0;">This shared note may have expired or been deleted.</p>
                  </div>
                </div>
                \;
            }
        })();
        
        // Stop React from loading
        const scripts = document.querySelectorAll('script[src*="index-"]');
        scripts.forEach(script => script.remove());
        
        // Force stop all further loading (including React module scripts)
        if (window.stop) {
          window.stop();
        }
    }
})();
