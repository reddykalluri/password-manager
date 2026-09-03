// Popup: unlock, matched-items-first list, search, copy, generator, and an
// inline new-item form pre-populated with the current site (browser-extensions
// spec: popup vault access).

import type { CaptureDecision } from '../lib/capture';
import { registrableDomain } from '../lib/matching';
import type { Candidate, Credential, ExtRequest, State } from '../lib/messages';

const app = document.getElementById('app') as HTMLElement;
const live = document.getElementById('live') as HTMLElement;

function say(m: string) {
  live.textContent = '';
  setTimeout(() => (live.textContent = m), 10);
}

async function bg<T>(msg: ExtRequest): Promise<T | null> {
  const r = await chrome.runtime.sendMessage(msg);
  return r?.ok ? (r.data as T) : null;
}

async function activeTabUrl(): Promise<string> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab?.url ?? '';
}

async function fillInPage(id: string) {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.id) chrome.tabs.sendMessage(tab.id, { type: 'FILL_IN_PAGE', id });
  window.close();
}

async function copyField(id: string, field: 'username' | 'password') {
  const cred = await bg<Credential | null>({ type: 'FILL', id });
  if (!cred) return;
  await navigator.clipboard.writeText(field === 'username' ? cred.username : cred.password);
  say(`${field} copied`);
}

function el(html: string): HTMLElement {
  const d = document.createElement('div');
  d.innerHTML = html.trim();
  return d.firstElementChild as HTMLElement;
}

async function render() {
  const state = await bg<State>({ type: 'GET_STATE' });
  if (!state?.unlocked) return renderUnlock();
  return renderVault();
}

function renderUnlock() {
  app.innerHTML = `
    <input id="url" placeholder="https://vault.example.com" autocomplete="url" />
    <input id="user" placeholder="Username" autocomplete="username" />
    <input id="pass" type="password" placeholder="Master password" autocomplete="current-password" />
    <input id="totp" placeholder="2FA code (if enabled)" inputmode="numeric" />
    <button class="primary" id="unlock">Unlock</button>
    <p id="err" style="color:#b3261e"></p>`;
  document.getElementById('unlock')!.addEventListener('click', async () => {
    const val = (id: string) => (document.getElementById(id) as HTMLInputElement).value.trim();
    try {
      const r = await chrome.runtime.sendMessage({
        type: 'UNLOCK',
        instanceUrl: val('url'),
        username: val('user'),
        password: val('pass'),
        totp: val('totp') || undefined
      });
      if (!r?.ok) throw new Error(r?.error ?? 'unlock failed');
      render();
    } catch (e) {
      document.getElementById('err')!.textContent = (e as Error).message;
    }
  });
}

function rowFor(c: Candidate): HTMLElement {
  const row = el(`
    <li>
      <span class="t">${escape(c.title)}<span class="u">${escape(c.username)}</span></span>
      <span class="row"></span>
    </li>`);
  const actions = row.querySelector('.row')!;
  const fillBtn = el(`<button class="primary">Fill</button>`);
  fillBtn.addEventListener('click', () => fillInPage(c.id));
  const userBtn = el(`<button title="Copy username">U</button>`);
  userBtn.addEventListener('click', () => copyField(c.id, 'username'));
  const passBtn = el(`<button title="Copy password">P</button>`);
  passBtn.addEventListener('click', () => copyField(c.id, 'password'));
  actions.append(fillBtn, userBtn, passBtn);
  return row;
}

async function renderVault() {
  const url = await activeTabUrl();
  const site = registrableDomain(url) ?? '';
  const pending = await bg<CaptureDecision | null>({ type: 'GET_PENDING' });
  const matched = (await bg<Candidate[]>({ type: 'CANDIDATES', url })) ?? [];

  app.innerHTML = '';
  if (pending && pending.action !== 'none') app.append(pendingBanner(pending, url, site));

  const search = el(`<input id="q" placeholder="Search vault" />`) as HTMLInputElement;
  const lock = el(`<button id="lock">Lock</button>`);
  lock.addEventListener('click', async () => {
    await chrome.runtime.sendMessage({ type: 'LOCK' });
    render();
  });
  const bar = el(`<div class="row"></div>`);
  bar.append(search, lock);
  app.append(bar);

  const list = el(`<ul id="list"></ul>`);
  app.append(list);
  const show = (items: Candidate[]) => {
    list.innerHTML = '';
    if (items.length === 0) list.append(el(`<li><span class="u">No items</span></li>`));
    for (const c of items) list.append(rowFor(c));
  };
  show(matched); // matched items for the active tab first

  search.addEventListener('input', async () => {
    const q = search.value.trim();
    show(q ? ((await bg<Candidate[]>({ type: 'SEARCH', query: q })) ?? []) : matched);
  });

  app.append(generatorBlock());
  app.append(newItemBlock(url, site));
}

function pendingBanner(p: CaptureDecision, url: string, site: string): HTMLElement {
  const banner = el(`<div class="banner"></div>`);
  if (p.action === 'save') {
    banner.append(el(`<div>Save login for <b>${escape(site)}</b>?</div>`));
    const btn = el(`<button class="primary">Save</button>`);
    btn.addEventListener('click', async () => {
      await chrome.runtime.sendMessage({
        type: 'SAVE',
        baseDomain: site,
        url,
        username: p.username,
        password: p.password
      });
      render();
    });
    banner.append(btn);
  } else if (p.action === 'update') {
    banner.append(el(`<div>Update saved password for <b>${escape(site)}</b>?</div>`));
    const btn = el(`<button class="primary">Update</button>`);
    btn.addEventListener('click', async () => {
      await chrome.runtime.sendMessage({ type: 'UPDATE', id: p.id, newPassword: p.newPassword });
      render();
    });
    banner.append(btn);
  }
  const dismiss = el(`<button>Not now</button>`);
  dismiss.addEventListener('click', async () => {
    await chrome.runtime.sendMessage({ type: 'CLEAR_PENDING' });
    render();
  });
  banner.append(dismiss);
  return banner;
}

function generatorBlock(): HTMLElement {
  const block = el(`
    <details>
      <summary>Generator</summary>
      <div class="row"><input id="gen" readonly /><button id="regen">↻</button><button id="copygen">Copy</button></div>
    </details>`);
  const input = block.querySelector('#gen') as HTMLInputElement;
  const gen = async () => {
    const v = await bg<string>({
      type: 'GENERATE',
      kind: 'password',
      opts: { length: 20, lowercase: true, uppercase: true, digits: true, symbols: true }
    });
    input.value = v ?? '';
  };
  block.querySelector('#regen')!.addEventListener('click', gen);
  block.querySelector('#copygen')!.addEventListener('click', () => {
    navigator.clipboard.writeText(input.value);
    say('generated password copied');
  });
  gen();
  return block;
}

function newItemBlock(url: string, site: string): HTMLElement {
  const block = el(`
    <details>
      <summary>+ New login for ${escape(site)}</summary>
      <input id="nu" placeholder="Username" />
      <input id="np" type="password" placeholder="Password" />
      <button class="primary" id="add">Add</button>
    </details>`);
  block.querySelector('#add')!.addEventListener('click', async () => {
    const nu = (block.querySelector('#nu') as HTMLInputElement).value;
    const np = (block.querySelector('#np') as HTMLInputElement).value;
    if (!np) return;
    await chrome.runtime.sendMessage({
      type: 'SAVE',
      baseDomain: site,
      url,
      username: nu,
      password: np
    });
    render();
  });
  return block;
}

function escape(s: string): string {
  return s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

render();
