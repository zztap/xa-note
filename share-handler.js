(function () {
    // Check if current URL is a share link
    const path = window.location.pathname;
    const shareMatch = path.match(/^\/share\/([a-zA-Z0-9_-]+)$/);

    if (shareMatch) {
        const shareCode = shareMatch[1];
        console.log('📤 Share page detected:', shareCode);

        // Prevent React app from loading
        const root = document.getElementById('root');
        root.innerHTML = '\u003cdiv id="share-container"\u003e\u003c/div\u003e';

        // Fetch and render shared note
        (async function loadSharedNote() {
            const container = document.getElementById('share-container');

            // Show loading state
            container.innerHTML = `
        \u003cdiv style="min-height: 100vh; display: flex; align-items: center; justify-content: center; font-family: system-ui, -apple-system, sans-serif;"\u003e
          \u003cdiv style="text-align: center;"\u003e
            \u003cdiv style="font-size: 2rem; margin-bottom: 1rem;"\u003e📝\u003c/div\u003e
            \u003cdiv style="color: #666;"\u003eLoading shared note...\u003c/div\u003e
          \u003c/div\u003e
        \u003c/div\u003e
      `;

            try {
                // Fetch shared note
                const response = await fetch(\`/api/share/\${shareCode}/view\`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({})
        });
        
        if (!response.ok) {
          throw new Error(\`HTTP \${response.status}\`);
        }
        
        const note = await response.json();
        
        // Render shared note
        container.innerHTML = `
                \u003cdiv style = "min-height: 100vh; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 2rem;"\u003e
                \u003cdiv style = "max-width: 800px; margin: 0 auto; background: white; border-radius: 16px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); overflow: hidden;"\u003e
                \u003cdiv style = "background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 2rem; color: white;"\u003e
                \u003ch1 style = "margin: 0; font-size: 2rem; font-weight: 600;"\u003e\${ note.title || 'Untitled Note' } \u003c / h1\u003e
                \u003cdiv style = "margin-top: 0.5rem; opacity: 0.9; font-size: 0.9rem;"\u003e
                  📤 Shared Note • Created: \${ new Date(note.created_at).toLocaleDateString() }
                \u003c / div\u003e
                \u003c / div\u003e
                \u003cdiv style = "padding: 2rem;"\u003e
                \u003cdiv id = "note-content" style = "line-height: 1.8; color: #333; font-size: 1rem;"\u003e\u003c / div\u003e
                \u003c / div\u003e
                \u003cdiv style = "padding: 1.5rem 2rem; background: #f8f9fa; border-top: 1px solid #e9ecef; text-align: center; color: #666; font-size: 0.875rem;"\u003e
                Powered by \u003cstrong\u003eXA Note\u003c / strong\u003e
                \u003c / div\u003e
                \u003c / div\u003e
                \u003c / div\u003e
                    `;
        
        // Render markdown content
        const contentDiv = document.getElementById('note-content');
        if (note.content) {
          // Simple markdown-to-HTML conversion
          let html = note.content
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/^### (.*$)/gim, '\u003ch3 style="margin-top: 1.5rem; margin-bottom: 0.75rem; font-size: 1.25rem; font-weight: 600;"\u003e$1\u003c/h3\u003e')
            .replace(/^## (.*$)/gim, '\u003ch2 style="margin-top: 2rem; margin-bottom: 1rem; font-size: 1.5rem; font-weight: 600;"\u003e$1\u003c/h2\u003e')
            .replace(/^# (.*$)/gim, '\u003ch1 style="margin-top: 2rem; margin-bottom: 1rem; font-size: 1.875rem; font-weight: 700;"\u003e$1\u003c/h1\u003e')
            .replace(/\*\*([^*]+)\*\*/g, '\u003cstrong\u003e$1\u003c/strong\u003e')
            .replace(/\*([^*]+)\*/g, '\u003cem\u003e$1\u003c/em\u003e')
            .replace(/\`([^\`]+)\`/g, '\u003ccode style="background: #f1f3f5; padding: 0.2rem 0.4rem; border-radius: 4px; font-family: monospace; font-size: 0.9em;"\u003e$1\u003c/code\u003e')
            .replace(/\n\n/g, '\u003c/p\u003e\u003cp style="margin: 1rem 0;"\u003e')
            .replace(/\n/g, '\u003cbr\u003e');
          
          contentDiv.innerHTML = '\u003cp style="margin: 1rem 0;"\u003e' + html + '\u003c/p\u003e';
        } else {
          contentDiv.innerHTML = '\u003cp style="color: #999; font-style: italic;"\u003eThis note is empty.\u003c/p\u003e';
        }
        
      } catch (error) {
        console.error('Failed to load shared note:', error);
        container.innerHTML = `
                \u003cdiv style = "min-height: 100vh; display: flex; align-items: center; justify-content: center; font-family: system-ui, -apple-system, sans-serif;"\u003e
                \u003cdiv style = "text-align: center; max-width: 400px; padding: 2rem;"\u003e
                \u003cdiv style = "font-size: 3rem; margin-bottom: 1rem;"\u003e❌\u003c / div\u003e
                \u003ch2 style = "margin: 0 0 0.5rem 0; color: #333;"\u003eShare Not Found\u003c / h2\u003e
                \u003cp style = "color: #666; margin: 0;"\u003eThis shared note may have expired or been deleted.\u003c / p\u003e
                \u003c / div\u003e
                \u003c / div\u003e
                    `;
      }
    })();
    
    // Stop React from loading
    const scripts = document.querySelectorAll('script[src*="index-"]');
    scripts.forEach(script =\u003e script.remove());
  }
})();
