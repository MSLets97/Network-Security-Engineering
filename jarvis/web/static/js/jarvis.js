/* J.A.R.V.I.S. Frontend — real-time chat + voice */
'use strict';

// ── Grid background canvas ───────────────────────────────
(function initGrid() {
  const canvas = document.getElementById('grid-canvas');
  const ctx = canvas.getContext('2d');
  const SPACING = 40;
  const COLOUR = '#00d4ff';

  function draw() {
    canvas.width  = window.innerWidth;
    canvas.height = window.innerHeight;
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.strokeStyle = COLOUR;
    ctx.lineWidth = 0.5;
    for (let x = 0; x < canvas.width; x += SPACING) {
      ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, canvas.height); ctx.stroke();
    }
    for (let y = 0; y < canvas.height; y += SPACING) {
      ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(canvas.width, y); ctx.stroke();
    }
  }
  draw();
  window.addEventListener('resize', draw);
})();

// ── SocketIO setup ───────────────────────────────────────
const socket = io({ transports: ['websocket', 'polling'] });

// ── DOM references ───────────────────────────────────────
const chatWindow   = document.getElementById('chat-window');
const userInput    = document.getElementById('user-input');
const btnSend      = document.getElementById('btn-send');
const btnClear     = document.getElementById('btn-clear');
const btnVoice     = document.getElementById('btn-voice');
const thinkingBar  = document.getElementById('thinking-bar');
const statusText   = document.getElementById('status-text');

// ── Markdown renderer ────────────────────────────────────
marked.setOptions({
  breaks: true,
  gfm: true,
  headerIds: false,
  mangle: false,
});

// ── State ────────────────────────────────────────────────
let activeJarvisMsg  = null;
let streamBuffer     = '';
let isStreaming      = false;
let voiceEnabled     = false;
let recognition      = null;

// ── Helpers ──────────────────────────────────────────────
function scrollToBottom() {
  chatWindow.scrollTop = chatWindow.scrollHeight;
}

function setStatus(text, cls = '') {
  statusText.textContent = text;
  statusText.className = 'stat-value' + (cls ? ' ' + cls : '');
}

function appendMessage(role, html) {
  const wrap = document.createElement('div');
  wrap.className = 'message ' + (
    role === 'user'   ? 'user-msg'   :
    role === 'jarvis' ? 'jarvis-msg' : 'system-msg'
  );
  const label = document.createElement('div');
  label.className = 'msg-label';
  label.textContent =
    role === 'user'   ? 'YOU'    :
    role === 'jarvis' ? 'JARVIS' : 'SYSTEM';
  const body = document.createElement('div');
  body.className = 'msg-body';
  body.innerHTML = html;
  wrap.appendChild(label);
  wrap.appendChild(body);
  chatWindow.appendChild(wrap);
  scrollToBottom();
  return wrap;
}

function startJarvisStream() {
  streamBuffer = '';
  isStreaming  = true;
  const wrap = document.createElement('div');
  wrap.className = 'message jarvis-msg';
  const label = document.createElement('div');
  label.className = 'msg-label';
  label.textContent = 'JARVIS';
  const body = document.createElement('div');
  body.className = 'msg-body streaming-cursor';
  wrap.appendChild(label);
  wrap.appendChild(body);
  chatWindow.appendChild(wrap);
  activeJarvisMsg = { wrap, body };
  scrollToBottom();
}

function appendChunk(text) {
  if (!activeJarvisMsg) return;
  streamBuffer += text;
  activeJarvisMsg.body.innerHTML = marked.parse(streamBuffer);
  scrollToBottom();
}

function finaliseStream() {
  if (!activeJarvisMsg) return;
  activeJarvisMsg.body.classList.remove('streaming-cursor');
  activeJarvisMsg.body.innerHTML = marked.parse(streamBuffer);
  activeJarvisMsg = null;
  streamBuffer = '';
  isStreaming = false;
  scrollToBottom();
}

function setInputLocked(locked) {
  btnSend.disabled    = locked;
  userInput.disabled  = locked;
  thinkingBar.classList.toggle('visible', locked);
  setStatus(locked ? 'PROCESSING' : 'ONLINE');
}

// ── Send message ─────────────────────────────────────────
function sendMessage(text) {
  if (!text.trim() || isStreaming) return;
  appendMessage('user', marked.parse(text));
  socket.emit('message', { text });
  userInput.value = '';
  autoResize();
  setInputLocked(true);
  startJarvisStream();
}

// ── Socket events ─────────────────────────────────────────
socket.on('connect', () => setStatus('ONLINE'));
socket.on('disconnect', () => setStatus('OFFLINE'));

socket.on('status', (data) => {
  appendMessage('system', data.message);
  setStatus('ONLINE');
});

socket.on('thinking', () => {
  setInputLocked(true);
});

socket.on('chunk', (data) => {
  appendChunk(data.text);
});

socket.on('done', () => {
  finaliseStream();
  setInputLocked(false);
  userInput.focus();
});

socket.on('error', (data) => {
  finaliseStream();
  appendMessage('system', `<span style="color:var(--red)">ERROR: ${data.message}</span>`);
  setInputLocked(false);
});

// ── Input controls ────────────────────────────────────────
function autoResize() {
  userInput.style.height = 'auto';
  userInput.style.height = Math.min(userInput.scrollHeight, 150) + 'px';
}

userInput.addEventListener('input', autoResize);
userInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    sendMessage(userInput.value);
  }
});
btnSend.addEventListener('click', () => sendMessage(userInput.value));

btnClear.addEventListener('click', () => {
  socket.emit('clear');
  chatWindow.innerHTML = '';
  appendMessage('system', 'Conversation history cleared.');
});

// ── Voice input ───────────────────────────────────────────
(function initVoice() {
  const SpeechRec = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (!SpeechRec) {
    btnVoice.title = 'Voice not supported in this browser';
    btnVoice.style.opacity = '0.4';
    return;
  }

  recognition = new SpeechRec();
  recognition.lang = 'en-GB';
  recognition.interimResults = false;
  recognition.maxAlternatives = 1;

  recognition.onresult = (e) => {
    const transcript = e.results[0][0].transcript;
    userInput.value = transcript;
    autoResize();
    sendMessage(transcript);
  };

  recognition.onstart = () => {
    btnVoice.classList.add('recording');
    btnVoice.textContent = 'REC';
  };

  recognition.onend = () => {
    btnVoice.classList.remove('recording');
    btnVoice.textContent = 'MIC';
    voiceEnabled = false;
  };

  recognition.onerror = (e) => {
    btnVoice.classList.remove('recording');
    btnVoice.textContent = 'MIC';
    voiceEnabled = false;
    if (e.error !== 'no-speech') {
      appendMessage('system', `Voice error: ${e.error}`);
    }
  };

  btnVoice.addEventListener('click', () => {
    if (voiceEnabled) {
      recognition.stop();
      voiceEnabled = false;
    } else {
      voiceEnabled = true;
      recognition.start();
    }
  });
})();

// ── Initial focus ─────────────────────────────────────────
userInput.focus();
