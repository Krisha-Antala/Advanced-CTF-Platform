(function () {
  const icon = document.getElementById('ai-helper-icon');
  const panel = document.getElementById('ai-helper-chat');
  const closeBtn = document.getElementById('ai-helper-close');
  const form = document.getElementById('chat-form');
  const input = document.getElementById('chat-input');
  const messages = document.getElementById('chat-messages');
  const typingIndicator = document.getElementById('typing-indicator');

  if (!icon || !panel || !form || !input || !messages) return;

  const context = window.CTF_CONTEXT || {
    challenge_id: null,
    challenge_name: "General",
    challenge_desc: "Explore and find vulnerabilities.",
    ciphertext: ""
  };

  icon.onclick = () => {
    panel.style.display = 'flex';
    panel.style.animation = 'slideUp 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275) forwards';
    input.focus();
  };

  closeBtn.onclick = () => {
    panel.style.display = 'none';
  };

  form.onsubmit = async (e) => {
    e.preventDefault();
    const question = input.value.trim();
    if (!question) return;

    appendMessage("You", question, true);
    input.value = "";

    // Show typing indicator
    if (typingIndicator) typingIndicator.style.display = 'flex';
    messages.scrollTop = messages.scrollHeight;

    try {
      const res = await fetch("/api/ai_helper", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question, context })
      });

      const data = await res.json();

      // Artificial delay for realism
      setTimeout(() => {
        if (typingIndicator) typingIndicator.style.display = 'none';
        appendMessage("AI Assistant", data.answer || "I'm having trouble processing that query. Please try again.", false);
      }, 800 + Math.random() * 1000);

    } catch (err) {
      if (typingIndicator) typingIndicator.style.display = 'none';
      appendMessage("System", "⚠️ Connection to neural link lost. Deployment failed.", false);
    }
  };

  function appendMessage(sender, text, isUser) {
    const msg = document.createElement("div");
    msg.style.maxWidth = "85%";
    msg.style.padding = "12px 16px";
    msg.style.borderRadius = isUser ? "15px 15px 0 15px" : "15px 15px 15px 0";
    msg.style.fontSize = "0.95rem";
    msg.style.lineHeight = "1.5";
    msg.style.alignSelf = isUser ? "flex-end" : "flex-start";
    msg.style.background = isUser ? "rgba(99, 102, 241, 0.2)" : "rgba(255, 255, 255, 0.05)";
    msg.style.border = isUser ? "1px solid rgba(99, 102, 241, 0.3)" : "1px solid rgba(255, 255, 255, 0.05)";
    msg.style.color = isUser ? "#fff" : "#e5e7eb";
    msg.style.boxShadow = "0 4px 12px rgba(0,0,0,0.1)";
    msg.style.opacity = "0";
    msg.style.transform = "translateY(10px)";
    msg.style.transition = "all 0.3s ease";

    // Basic Markdown Simulation
    let formattedText = text
      .replace(/\n/g, '<br>')
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/\*(.*?)\*/g, '<em>$1</em>')
      .replace(/`(.*?)`/g, '<code style="background: rgba(0,0,0,0.3); padding: 2px 5px; border-radius: 4px; font-family: monospace; color: #f472b6;">$1</code>');

    msg.innerHTML = formattedText;
    messages.appendChild(msg);

    // Trigger animation
    setTimeout(() => {
      msg.style.opacity = "1";
      msg.style.transform = "translateY(0)";
      messages.scrollTop = messages.scrollHeight;
    }, 10);
  }

  // Add styles for slide up animation
  const style = document.createElement('style');
  style.textContent = `
    @keyframes slideUp {
      from { opacity: 0; transform: translateY(30px) scale(0.95); }
      to { opacity: 1; transform: translateY(0) scale(1); }
    }
  `;
  document.head.appendChild(style);
})();
