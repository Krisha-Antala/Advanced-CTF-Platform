(function () {
  const icon = document.getElementById('ai-helper-icon');
  const panel = document.getElementById('ai-helper-chat');
  const closeBtn = document.getElementById('ai-helper-close');
  const form = document.getElementById('chat-form');
  const input = document.getElementById('chat-input');
  const messages = document.getElementById('chat-messages');

  if (!icon || !panel || !form || !input || !messages) return;

  // Use context if available, else fallback
  const context = window.CTF_CONTEXT || {
    challenge_id: null,
    challenge_name: "General",
    challenge_desc: "Ask me anything about CTFs, hacking, or cybersecurity!",
    ciphertext: ""
  };

  icon.onclick = () => {
    panel.style.display = 'flex';
    input.focus();
  };

  closeBtn.onclick = () => {
    panel.style.display = 'none';
  };

  form.onsubmit = async (e) => {
    e.preventDefault();
    const question = input.value.trim();
    if (!question) return;

    appendMessage("You", question);
    input.value = "";

    try {
      const res = await fetch("/api/ai_helper", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question, context })
      });

      const data = await res.json();
      appendMessage("Helper", data.answer || "Hmm... I couldn't find a good hint.");
    } catch (err) {
      appendMessage("Helper", "⚠️ Error reaching the server. Try again later.");
    }
  };

  function appendMessage(sender, text) {
    const msg = document.createElement("p");
    msg.innerHTML = `<strong>${sender}:</strong> ${text}`;
    messages.appendChild(msg);
    messages.scrollTop = messages.scrollHeight;
  }
})();