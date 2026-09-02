<script lang="ts">
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';
  import { session } from '$lib/session.svelte';
  import { api } from '$lib/api';
  import type { AuditEntry, DeviceView } from '$lib/types';
  import PasswordField from '$lib/components/PasswordField.svelte';

  $effect(() => {
    if (session.ready && !session.unlocked) goto('/unlock');
  });

  // --- session hardening prefs ---
  let lockSecs = $state(session.lockTimeoutSecs);
  let clipSecs = $state(session.clipboardClearSecs);
  function applyLock() {
    session.setLockTimeout(lockSecs);
  }
  function applyClip() {
    session.clipboardClearSecs = clipSecs;
  }

  // --- change master password ---
  let curPw = $state('');
  let newPw = $state('');
  let confirmPw = $state('');
  let cpTotp = $state('');
  let cpMsg = $state<string | null>(null);
  let cpBusy = $state(false);
  async function changePassword(e: SubmitEvent) {
    e.preventDefault();
    cpMsg = null;
    if (newPw !== confirmPw) {
      cpMsg = 'New passwords do not match.';
      return;
    }
    cpBusy = true;
    try {
      await session.changeMasterPassword(curPw, newPw, cpTotp ? { totp_code: cpTotp } : {});
      cpMsg = 'Master password changed.';
      curPw = newPw = confirmPw = cpTotp = '';
    } catch (err) {
      cpMsg = (err as Error).message;
    } finally {
      cpBusy = false;
    }
  }

  // --- recovery code ---
  let recPw = $state('');
  let recCode = $state<string | null>(null);
  let recBusy = $state(false);
  let recTotp = $state('');
  async function regenRecovery(e: SubmitEvent) {
    e.preventDefault();
    recBusy = true;
    try {
      recCode = await session.regenerateRecoveryCode(recPw);
      await session.uploadCryptoAfterRecoveryRegen(recTotp ? { totp_code: recTotp } : {});
      recPw = recTotp = '';
    } catch (err) {
      recCode = null;
      session.say((err as Error).message);
    } finally {
      recBusy = false;
    }
  }

  // --- TOTP enrolment ---
  function base32(bytes: Uint8Array): string {
    const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = 0,
      val = 0,
      out = '';
    for (const b of bytes) {
      val = (val << 8) | b;
      bits += 8;
      while (bits >= 5) {
        out += A[(val >>> (bits - 5)) & 31];
        bits -= 5;
      }
    }
    if (bits > 0) out += A[(val << (5 - bits)) & 31];
    return out;
  }
  let totpSecret = $state('');
  let totpCode = $state('');
  let totpMsg = $state<string | null>(null);
  function genTotpSecret() {
    const raw = new Uint8Array(20);
    crypto.getRandomValues(raw);
    totpSecret = base32(raw);
    totpMsg = null;
  }
  async function enrollTotp(e: SubmitEvent) {
    e.preventDefault();
    try {
      await api.enrollTotp(totpSecret, totpCode);
      totpMsg = 'Authenticator enrolled.';
      totpSecret = totpCode = '';
    } catch (err) {
      totpMsg = (err as Error).message;
    }
  }

  // --- activity + devices ---
  let activity = $state<AuditEntry[]>([]);
  let devices = $state<DeviceView[]>([]);
  onMount(async () => {
    try {
      activity = await api.activity();
      devices = await api.devices();
    } catch {
      /* ignore; shown empty */
    }
  });
</script>

<h1>Settings</h1>

<section>
  <h2>Session hardening</h2>
  <label for="lock">Auto-lock after (seconds, 0 = never)</label>
  <input id="lock" type="number" min="0" bind:value={lockSecs} onchange={applyLock} />
  <label for="clip">Clear clipboard after (seconds)</label>
  <input id="clip" type="number" min="5" bind:value={clipSecs} onchange={applyClip} />
</section>

<section>
  <h2>Change master password</h2>
  <form onsubmit={changePassword}>
    <PasswordField id="cur" label="Current password" bind:value={curPw} copyable={false} autocomplete="current-password" />
    <PasswordField id="new" label="New password" bind:value={newPw} copyable={false} autocomplete="new-password" />
    <PasswordField id="conf" label="Confirm new password" bind:value={confirmPw} copyable={false} autocomplete="new-password" />
    <label for="cptotp">Authenticator code <span class="muted">(if 2FA enabled)</span></label>
    <input id="cptotp" bind:value={cpTotp} inputmode="numeric" maxlength="6" />
    {#if cpMsg}<p role="alert">{cpMsg}</p>{/if}
    <button class="primary" type="submit" disabled={cpBusy}>Change password</button>
  </form>
</section>

<section>
  <h2>Recovery code</h2>
  <p class="muted">Generates a new code and invalidates the old one.</p>
  <form onsubmit={regenRecovery}>
    <PasswordField id="recpw" label="Master password" bind:value={recPw} copyable={false} autocomplete="current-password" />
    <label for="rectotp">Authenticator code <span class="muted">(if 2FA enabled)</span></label>
    <input id="rectotp" bind:value={recTotp} inputmode="numeric" maxlength="6" />
    <button type="submit" disabled={recBusy}>Regenerate recovery code</button>
  </form>
  {#if recCode}
    <p>Save this now — it is shown once:</p>
    <output class="code">{recCode}</output>
  {/if}
</section>

<section>
  <h2>Two-factor authentication (TOTP)</h2>
  <button onclick={genTotpSecret}>Generate secret</button>
  {#if totpSecret}
    <form onsubmit={enrollTotp}>
      <label for="secret">Add this secret to your authenticator app</label>
      <output id="secret" class="code">{totpSecret}</output>
      <label for="tcode">Enter the current 6-digit code to confirm</label>
      <input id="tcode" bind:value={totpCode} inputmode="numeric" maxlength="6" required />
      <button class="primary" type="submit">Enable</button>
    </form>
  {/if}
  {#if totpMsg}<p role="alert">{totpMsg}</p>{/if}
</section>

<section>
  <h2>Devices</h2>
  {#if devices.length}
    <ul>{#each devices as d (d.id)}<li>{d.name}</li>{/each}</ul>
  {:else}
    <p class="muted">No devices listed.</p>
  {/if}
</section>

<section>
  <h2>Security activity</h2>
  {#if activity.length}
    <ul class="activity">
      {#each activity as a (a.created_at + a.event)}
        <li>
          <strong>{a.event}</strong>
          <span class="muted">{new Date(a.created_at).toLocaleString()}{a.ip ? ` · ${a.ip}` : ''}</span>
        </li>
      {/each}
    </ul>
  {:else}
    <p class="muted">No recent activity.</p>
  {/if}
</section>

<style>
  section {
    border-top: 1px solid var(--border);
    padding: 16px 0;
    max-width: 34rem;
  }
  .muted {
    color: var(--muted);
    font-weight: 400;
  }
  .code {
    display: block;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    padding: 12px;
    border: 2px dashed var(--accent);
    border-radius: var(--radius);
    word-break: break-all;
    margin: 8px 0;
  }
  .activity {
    list-style: none;
    padding: 0;
  }
  .activity li {
    display: flex;
    justify-content: space-between;
    gap: 12px;
    padding: 6px 0;
    border-bottom: 1px solid var(--border);
    flex-wrap: wrap;
  }
  button[type='submit'] {
    margin-top: 12px;
  }
</style>
