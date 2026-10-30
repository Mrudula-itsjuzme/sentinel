const $ = id => document.getElementById(id);
const label = value => value ? String(value).replaceAll('_', ' ') : '—';

function openTab(name) {
  document.querySelectorAll('.tab').forEach(tab => tab.classList.toggle('active', tab.dataset.tab === name));
  document.querySelectorAll('.tab-panel').forEach(panel => panel.classList.toggle('active', panel.dataset.panel === name));
}

document.querySelectorAll('.tab').forEach(tab => tab.addEventListener('click', () => openTab(tab.dataset.tab)));
document.querySelectorAll('[data-open-tab]').forEach(button => button.addEventListener('click', () => openTab(button.dataset.openTab)));

// Keep the global product navigation connected to the incident workspace.
// These are intentionally local view changes; no navigation or data mutation
// happens until the analyst presses an explicit response action.
const navViews = {
  '#': 'workspace',
  '#workspace': 'workspace',
  '#twin': 'twin',
  '#audit': 'audit',
  '#policy': 'workspace',
  '#research': 'workspace'
};
document.querySelectorAll('.sidebar a[href^="#"]').forEach(link => link.addEventListener('click', event => {
  const target = link.getAttribute('href');
  const tab = navViews[target];
  if (!tab) return;
  event.preventDefault();
  openTab(tab);
  const targetId = target === '#policy' ? 'policy' : target === '#research' ? 'research' : null;
  if (targetId) document.getElementById(targetId)?.scrollIntoView({behavior: 'smooth', block: 'start'});
}));

// The empty-state CTA is rendered in the initial HTML and can be replaced by
// a response table, so use delegation for a stable interaction path.
document.addEventListener('click', event => {
  if (event.target.closest('[data-run-response]')) run(null);
});

async function loadConfig() {
  const config = await fetch('/config/model').then(response => response.json());
  $('model-state').textContent = config.configured ? `${config.model} · configured` : 'Fallback · no API call';
  $('live-model').disabled = !config.configured;
  $('live-model').title = config.configured ? 'Use the configured live model' : 'Set NEBIUS_API_KEY and NEBIUS_MODEL to enable';
}

async function loadExperiments() {
  const rows = await fetch('/experiments').then(response => response.json());
  const wanted = ['retry-then-fallback-default', 'structural-switch-controller', 'optimal-bounded-sequence'];
  $('experiment-bars').innerHTML = rows.filter(row => wanted.includes(row.method)).map(row => `
    <div class="bar"><span>${label(row.method)}</span><div><i style="width:${row.final_resolution_rate * 100}%"></i></div><strong>${(row.final_resolution_rate * 100).toFixed(1)}%</strong></div>
  `).join('');
}

function renderEvidence(evidence) {
  $('evidence-count').textContent = evidence.observations.length;
  $('evidence-panel-count').textContent = `${evidence.observations.length} signals`;
  $('evidence-list').innerHTML = evidence.observations.map(item => `
    <article><div class="evidence-source">${item.source}</div><div><strong>${item.detail}</strong><p>${label(item.kind)} · ${item.subject}</p></div><span>${Math.round(item.confidence * 100)}%</span><time>${new Date(item.observed_at).toISOString().slice(11, 19)} UTC</time></article>
  `).join('');
}

function renderCandidate(item) {
  const simulation = item.simulation;
  const policy = item.policy;
  return `<tr class="${item.selected ? 'selected-row' : ''}">
    <td><div class="action-cell"><i></i><span><strong>${label(simulation.action)}</strong><small>${item.selected ? 'Selected for execution' : item.proposed ? 'AI proposed' : 'Evaluated candidate'}</small></span></div></td>
    <td>${simulation.target}</td>
    <td><strong class="${simulation.security.attack_stopped ? 'good' : 'warn'}">${simulation.security.attack_stopped ? 'Attack stopped' : 'Residual risk'}</strong><small>${simulation.security.remaining_attack_paths} paths remain</small></td>
    <td><strong>${simulation.operations.users_impacted} users · ${simulation.operations.estimated_downtime_minutes} min</strong><small>Payroll ${simulation.operations.payroll_available ? 'available' : 'disrupted'}</small></td>
    <td><span class="decision ${policy.decision.toLowerCase()}">${policy.decision}</span><small>${label(policy.code)}</small></td>
  </tr>`;
}

function renderTwin(item) {
  const simulation = item.simulation;
  return `<tr><td><strong>${label(simulation.action)}</strong><small>${simulation.target}</small></td><td class="${simulation.security.attack_stopped ? 'good' : 'warn'}">${simulation.security.attack_stopped ? 'Yes' : 'No'}</td><td>${simulation.security.remaining_attack_paths}</td><td>${simulation.operations.users_impacted}</td><td>${simulation.operations.estimated_downtime_minutes} min</td><td class="${simulation.operations.payroll_available ? 'good' : 'bad'}">${simulation.operations.payroll_available ? 'Available' : 'Disrupted'}</td></tr>`;
}

function timelineMarkup(event, compact = false) {
  const timestamp = new Date(event.timestamp).toISOString().slice(11, 19);
  return `<li class="${event.state.toLowerCase()}"><i></i><div>${compact ? '' : `<time>${timestamp} UTC</time>`}<strong>${label(event.state)}</strong>${compact ? '' : `<small>${event.component}</small>`}<p>${event.summary}${event.action ? ` · ${label(event.action)}` : ''}</p></div></li>`;
}

function setRule(id, passed) {
  $(id).textContent = passed ? 'PASS' : 'FAIL';
  $(id).className = passed ? 'good' : 'bad';
}

function render(report) {
  renderEvidence(report.evidence);
  $('candidate-rows').innerHTML = report.candidate_assessments.map(renderCandidate).join('');
  $('twin-rows').innerHTML = report.candidate_assessments.map(renderTwin).join('');

  const call = report.model_call;
  $('reasoning-badge').textContent = call.fallback_used ? 'Deterministic fallback · no inference' : `${call.provider} · live response`;
  $('reasoning-badge').className = `reasoning-badge ${call.fallback_used ? 'fallback' : 'live'}`;
  const provenance = call.fallback_used
    ? `No AI inference occurred${call.requested ? `; the live call failed (${call.error_code || 'unknown error'})` : '; live reasoning was not requested'}.`
    : `Validated live ${call.model} response${call.latency_ms == null ? '' : ` in ${call.latency_ms} ms`}${call.total_tokens == null ? '; usage not returned' : `; ${call.total_tokens} tokens reported`}.`;
  $('diagnosis').textContent = `${report.diagnosis} ${provenance}`;

  const proposed = report.candidate_assessments.find(item => item.proposed);
  $('proposed-action').textContent = `${label(report.proposed_action)} · ${report.proposed_target}`;
  $('policy-state').textContent = proposed.policy.decision;
  $('policy-state').className = `decision ${proposed.policy.decision.toLowerCase()}`;
  $('policy-reason').textContent = proposed.policy.reason;
  setRule('rule-action', proposed.policy.code !== 'ACTION_NOT_ALLOWLISTED');
  setRule('rule-users', proposed.simulation.operations.users_impacted <= 1);
  setRule('rule-payroll', proposed.simulation.operations.payroll_available);
  setRule('rule-simulation', proposed.simulation.simulation_succeeded);

  const receipt = report.execution_receipt;
  $('receipt-action').textContent = label(receipt.action);
  $('receipt-target').textContent = receipt.target || '—';
  $('execution-state').textContent = label(receipt.result);
  $('execution-state').className = receipt.result === 'SIMULATED_SUCCESS' ? 'good' : 'bad';
  $('verify-paths').textContent = report.verification.attack_paths_remaining;
  $('verify-paths').className = report.verification.attack_paths_remaining === 0 ? 'good' : 'bad';
  $('verify-payroll').textContent = report.verification.payroll_available ? 'Available' : 'Unavailable';
  $('verify-payroll').className = report.verification.payroll_available ? 'good' : 'bad';
  $('verified-state').textContent = report.verification.recovered ? 'VERIFIED' : 'NOT VERIFIED';
  $('verified-state').className = `status ${report.verification.recovered ? 'recovered' : 'blocked'}`;
  $('header-status').textContent = report.status;
  $('header-status').className = `status ${report.status === 'RECOVERED' ? 'recovered' : 'blocked'}`;

  $('event-count').textContent = `${report.timeline.length} events`;
  $('timeline-full').innerHTML = report.timeline.map(event => timelineMarkup(event)).join('');
  $('timeline-compact').innerHTML = report.timeline.slice(-6).reverse().map(event => timelineMarkup(event, true)).join('');
  $('notice').innerHTML = `<span></span><p><strong>${report.status === 'RECOVERED' ? 'Response verified' : 'Response requires attention'}</strong>${call.fallback_used ? 'Completed with deterministic fallback. No AI inference is claimed.' : 'Completed with a validated live Nebius model response.'}</p>`;
  $('notice').className = `notice ${report.status === 'RECOVERED' ? 'success' : 'warning'}`;
}

async function run(proposedAction) {
  document.querySelectorAll('#run-safe, #run-block').forEach(button => button.disabled = true);
  $('notice').innerHTML = '<span></span><p><strong>Response in progress</strong>Reasoning, simulating, evaluating policy, and verifying…</p>';
  $('notice').className = 'notice running';
  openTab('workspace');
  try {
    const body = {use_live_reasoning: $('live-model').checked};
    if (proposedAction) body.proposed_action = proposedAction;
    const response = await fetch('/incidents', {method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify(body)});
    if (!response.ok) throw new Error(`Incident run failed (HTTP ${response.status}).`);
    render(await response.json());
  } catch (error) {
    $('notice').innerHTML = `<span></span><p><strong>Response failed</strong>${error.message}</p>`;
    $('notice').className = 'notice error';
  } finally {
    document.querySelectorAll('#run-safe, #run-block').forEach(button => button.disabled = false);
  }
}

$('run-safe').addEventListener('click', () => run(null));
$('run-block').addEventListener('click', () => run('ISOLATE_HOST'));
loadConfig();
loadExperiments();
