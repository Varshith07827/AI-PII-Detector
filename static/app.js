document.addEventListener('DOMContentLoaded', () => {
  // --- DOM ELEMENTS ---
  const form = document.getElementById('detect-form');
  const textInput = document.getElementById('text');
  const fileInput = document.getElementById('file');
  const modeSelect = document.getElementById('mode');
  const minConfidenceInput = document.getElementById('minConfidence');
  const maskingSelect = document.getElementById('masking');
  const maskTypeSelect = document.getElementById('maskType');
  const includePlaceholders = document.getElementById('includePlaceholders');
  const summaryEl = document.getElementById('summary');
  const highlightedEl = document.getElementById('highlighted');
  const maskedEl = document.getElementById('masked');
  const alertsEl = document.getElementById('alerts');
  const maskBtn = document.getElementById('mask-btn');
  const processingOverlay = document.getElementById('processing-overlay');

  // --- CRITICAL CHECK ---
  const criticalElements = {
    form, textInput, fileInput, modeSelect, minConfidenceInput, maskingSelect, 
    maskTypeSelect, includePlaceholders, summaryEl, highlightedEl, 
    maskedEl, alertsEl, maskBtn
  };

  const missing = Object.entries(criticalElements)
    .filter(([name, el]) => !el)
    .map(([name]) => name);

  if (missing.length > 0) {
    console.error('CRITICAL: Missing DOM elements:', missing);
    if (alertsEl) {
      alertsEl.textContent = `SYSTEM ERROR: UI CORRUPTION DETECTED (${missing.join(', ')}). REFRESH REQUIRED.`;
      alertsEl.style.color = 'red';
    }
    return; // Stop execution
  }

  // --- STATE ---
  let latestText = '';
  let latestEntities = [];

  // --- EVENT LISTENERS ---

  // 1. File Input Feedback
  fileInput.addEventListener('change', () => {
    if (fileInput.files.length > 0) {
      const fileName = fileInput.files[0].name;
      textInput.value = ''; 
      textInput.placeholder = `// FILE LOADED: ${fileName}\n// READY TO SCAN...`;
      alertsEl.innerText = `> SOURCE: ${fileName}`;
      alertsEl.style.color = 'var(--cyan)';
    }
  });

  // 2. Main Detection Form Submit
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    clearAlerts();
    
    toggleProcessing(true);
    summaryEl.innerText = "// ESTABLISHING CONNECTION TO NEURAL ENGINE...";

    const fd = new FormData();
    fd.append('mode', modeSelect.value);
    fd.append('minConfidence', minConfidenceInput.value || '0.0');
    
    if (fileInput.files[0]) {
      fd.append('file', fileInput.files[0]);
    } else if (textInput.value.trim()) {
      fd.append('text', textInput.value);
    } else {
      toggleProcessing(false);
      showAlert("ERROR: NO INPUT DETECTED");
      return;
    }

    try {
      const res = await fetch('/api/detect', { method: 'POST', body: fd });
      const data = await res.json();

      if (!res.ok) throw new Error(data.error || 'Detection protocol failed');

      latestText = data.text || textInput.value || '';
      latestEntities = data.entities;

      populateMaskTypes(latestEntities);
      renderSummary(data);
      renderHighlights(latestText, data.entities);
      
      if (data.filtered_count > 0) {
        showAlert(`INFO: FILTERED ${data.filtered_count} LOW-CONFIDENCE ENTITIES`);
        alertsEl.style.color = 'var(--cyan)';
      }
      
      maskedEl.innerHTML = '<span class="text-muted">// AWAITING MASKING PROTOCOL...</span>';

    } catch (err) {
      showAlert(`SYSTEM ERROR: ${err.message}`);
      summaryEl.innerText = "// SYSTEM ERROR";
      summaryEl.className = 'status-bar p-2 font-mono small border-bottom border-cyan-dim text-center text-danger';
    } finally {
      toggleProcessing(false);
    }
  });

  // 3. Masking Button Click
  maskBtn.addEventListener('click', async () => {
    clearAlerts();

    if (!latestEntities.length && !latestText) {
      showAlert("ERROR: NO DATA TO MASK. RUN SCAN FIRST.");
      return;
    }

    maskedEl.innerHTML = '<span class="text-cyan blink">> APPLYING MASKING ALGORITHMS...</span>';

    const body = {
      text: latestText,
      mode: modeSelect.value,
      minConfidence: parseFloat(minConfidenceInput.value) || 0.0,
      masking: maskingSelect.value,
      includePlaceholders: includePlaceholders.checked,
      maskTypes: maskTypeSelect.value === 'all' ? [] : [maskTypeSelect.value],
    };

    try {
      const res = await fetch('/api/mask', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Masking failed');

      maskedEl.textContent = data.masked;
      
      if (data.filtered_count > 0) {
        showAlert(`INFO: MASKED WITH CONFIDENCE ≥${body.minConfidence} (FILTERED ${data.filtered_count})`);
        alertsEl.style.color = 'var(--cyan)';
      }
      
    } catch (err) {
      showAlert(`MASK ERROR: ${err.message}`);
      maskedEl.textContent = "// ERROR IN MASKING OUTPUT";
    }
  });

  // --- HELPER FUNCTIONS ---

  function toggleProcessing(isLoading) {
    if (processingOverlay) {
      if (isLoading) processingOverlay.classList.remove('d-none');
      else processingOverlay.classList.add('d-none');
    }
  }

  function showAlert(msg) {
    alertsEl.textContent = `> ${msg}`;
    alertsEl.style.color = '#ff4d4d';
  }

  function clearAlerts() {
    alertsEl.textContent = '';
  }

  function renderSummary(data) {
    const counts = data.risk.counts || {};
    const parts = Object.entries(counts).map(([k, v]) => `${k.toUpperCase()}: ${v}`);
    
    const compliance = Object.entries(data.risk.compliance || {})
      .filter(([_, val]) => val)
      .map(([k]) => k.toUpperCase())
      .join(', ');

    const riskLevel = data.risk.bucket ? data.risk.bucket.toUpperCase() : 'UNKNOWN';
    
    let logMsg = `RISK ASSESSMENT: [ ${riskLevel} ]`;
    if (parts.length > 0) logMsg += ` | DETECTIONS: ${parts.join(' • ')}`;
    if (compliance) logMsg += ` | COMPLIANCE: ${compliance}`;

    summaryEl.textContent = `// ${logMsg}`;

    summaryEl.className = 'status-bar p-2 font-mono small border-bottom border-cyan-dim text-center';
    
    if (data.risk.bucket === 'critical') summaryEl.classList.add('summary', 'critical');
    else if (data.risk.bucket === 'high') summaryEl.classList.add('summary', 'high');
    else if (data.risk.bucket === 'medium') summaryEl.classList.add('summary', 'medium');
    else summaryEl.classList.add('summary', 'low');
  }

  function renderHighlights(text, entities) {
    if (!text) {
      highlightedEl.innerHTML = '<span class="text-muted">// NO TEXT CONTENT PARSED</span>';
      return;
    }

    const sorted = [...entities].sort((a, b) => a.start - b.start);
    let cursor = 0;
    const fragments = [];

    for (const ent of sorted) {
      if (ent.start > cursor) {
        fragments.push(escapeHtml(text.slice(cursor, ent.start)));
      }
      
      const cls = ent.placeholder ? 'placeholder' : ent.sensitivity;
      fragments.push(`<span class="tag ${cls}" title="${ent.label.toUpperCase()}">${escapeHtml(text.slice(ent.start, ent.end))}</span>`);
      
      cursor = ent.end;
    }

    fragments.push(escapeHtml(text.slice(cursor)));
    highlightedEl.innerHTML = fragments.join('');
  }

  function populateMaskTypes(entities) {
    const seen = new Set(entities.map((e) => e.label));
    const current = maskTypeSelect.value;
    
    maskTypeSelect.innerHTML = '';
    
    const optAll = document.createElement('option');
    optAll.value = 'all';
    optAll.textContent = 'ALL TYPES';
    maskTypeSelect.appendChild(optAll);

    Array.from(seen).sort().forEach((label) => {
      const opt = document.createElement('option');
      opt.value = label;
      opt.textContent = label.toUpperCase();
      maskTypeSelect.appendChild(opt);
    });

    if ([...seen, 'all'].includes(current)) {
      maskTypeSelect.value = current;
    }
  }

  function escapeHtml(str) {
    return str.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  }
});
