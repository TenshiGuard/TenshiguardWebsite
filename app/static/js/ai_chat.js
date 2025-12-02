// app/static/js/ai_chat.js

function toggleChat() {
    const widget = document.getElementById('ai-chat-widget');
    widget.classList.toggle('collapsed');
}

function handleChatInput(event) {
    if (event.key === 'Enter') {
        sendChatMessage();
    }
}

async function sendChatMessage() {
    const input = document.getElementById('chat-input');
    const body = document.getElementById('chat-body');
    const message = input.value.trim();

    if (!message) return;

    // Add User Message
    appendMessage('user', message);
    input.value = '';

    // Show Typing Indicator
    const typingId = 'typing-' + Date.now();
    appendMessage('bot', '<i class="fa-solid fa-circle-notch fa-spin"></i> Thinking...', typingId);

    // Gather Context
    const context = {
        page_title: document.title,
        url: window.location.href,
        timestamp: new Date().toISOString(),
        // Try to grab visible stats if available (e.g., from cards)
        stats: {
            total_devices: document.querySelector('.tg-card h3')?.innerText || 'N/A',
            alerts_visible: document.querySelectorAll('.table tbody tr').length || 0
        }
    };

    try {
        const res = await fetch('/api/dashboard/ai/ask', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-API-KEY': 'tg-dashboard-key'
            },
            body: JSON.stringify({ prompt: message, context: context })
        });

        const data = await res.json();

        // Remove Typing Indicator
        const typingElem = document.getElementById(typingId);
        if (typingElem) typingElem.parentElement.remove();

        if (data.ok) {
            appendMessage('bot', formatAIResponse(data.response));
        } else {
            appendMessage('bot', 'Error: ' + (data.message || 'Could not reach AI.'));
        }

    } catch (err) {
        console.error(err);
        const typingElem = document.getElementById(typingId);
        if (typingElem) typingElem.parentElement.remove();
        appendMessage('bot', 'Connection error. Please try again.');
    }
}

function appendMessage(sender, html, id = null) {
    const body = document.getElementById('chat-body');
    const div = document.createElement('div');
    div.className = `chat-message ${sender}`;
    div.innerHTML = `<div class="message-content" ${id ? `id="${id}"` : ''}>${html}</div>`;
    body.appendChild(div);
    body.scrollTop = body.scrollHeight;
}

function formatAIResponse(text) {
    // Simple markdown-like formatting
    return text
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
        .replace(/\n/g, '<br>');
}
