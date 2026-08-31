<script lang="ts">
  import { goto } from '$app/navigation';
  import { session } from '$lib/session.svelte';
  import type { ItemContent } from '$lib/types';
  import PasswordField from '$lib/components/PasswordField.svelte';

  $effect(() => {
    if (session.ready && !session.unlocked) goto('/unlock');
  });

  // --- import ---
  let kind = $state<'csv' | 'bitwarden' | '1pux'>('csv');
  let data = $state('');
  let preview = $state<{ items: ItemContent[]; errors: { row: number; message: string }[] } | null>(null);
  let importMsg = $state<string | null>(null);

  async function onFile(e: Event) {
    const file = (e.target as HTMLInputElement).files?.[0];
    if (file) data = await file.text();
  }
  function doPreview() {
    importMsg = null;
    try {
      preview = session.importPreview(kind, data);
    } catch (err) {
      importMsg = (err as Error).message;
      preview = null;
    }
  }
  async function doCommit() {
    if (!preview) return;
    const n = await session.importCommit(preview.items);
    importMsg = `Imported ${n} item(s).`;
    preview = null;
    data = '';
  }

  // --- export ---
  function download(name: string, content: string, type: string) {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    a.click();
    URL.revokeObjectURL(url);
  }

  let exportPw = $state('');
  let exportMsg = $state<string | null>(null);
  function exportEncrypted(e: SubmitEvent) {
    e.preventDefault();
    exportMsg = null;
    try {
      const json = session.exportEncrypted(exportPw);
      download('vault-export.json', json, 'application/json');
      exportPw = '';
      exportMsg = 'Encrypted export downloaded.';
    } catch (err) {
      exportMsg = (err as Error).message;
    }
  }

  let csvPw = $state('');
  let csvAck = $state(false);
  let csvMsg = $state<string | null>(null);
  function exportCsv(e: SubmitEvent) {
    e.preventDefault();
    csvMsg = null;
    if (!csvAck) {
      csvMsg = 'You must acknowledge the plaintext risk.';
      return;
    }
    try {
      const csv = session.exportCsvGated(csvPw);
      download('vault-export.csv', csv, 'text/csv');
      csvPw = '';
      csvAck = false;
      csvMsg = 'Plaintext CSV downloaded.';
    } catch {
      csvMsg = 'Incorrect master password.';
    }
  }
</script>

<h1>Import &amp; Export</h1>

<section>
  <h2>Import</h2>
  <label for="kind">Format</label>
  <select id="kind" bind:value={kind}>
    <option value="csv">Generic CSV</option>
    <option value="bitwarden">Bitwarden JSON</option>
    <option value="1pux">1Password (export.data JSON)</option>
  </select>

  <label for="file">Choose a file</label>
  <input id="file" type="file" onchange={onFile} accept=".csv,.json,.txt" />

  <label for="paste">…or paste the exported data</label>
  <textarea id="paste" rows="6" bind:value={data}></textarea>

  <div class="actions">
    <button onclick={doPreview} disabled={!data}>Preview</button>
    {#if preview}
      <button class="primary" onclick={doCommit} disabled={preview.items.length === 0}>
        Import {preview.items.length} item(s)
      </button>
    {/if}
  </div>

  {#if importMsg}<p role="status">{importMsg}</p>{/if}
  {#if preview}
    <p>{preview.items.length} item(s) ready, {preview.errors.length} row error(s).</p>
    {#if preview.errors.length}
      <ul class="errs">
        {#each preview.errors as err (err.row)}
          <li>Row {err.row}: {err.message}</li>
        {/each}
      </ul>
    {/if}
  {/if}
</section>

<section>
  <h2>Export (encrypted)</h2>
  <p class="muted">Password-protected JSON. Safe to store anywhere.</p>
  <form onsubmit={exportEncrypted}>
    <PasswordField id="exp" label="Export password" bind:value={exportPw} copyable={false} autocomplete="new-password" />
    <button class="primary" type="submit" disabled={!exportPw}>Download encrypted export</button>
  </form>
  {#if exportMsg}<p role="status">{exportMsg}</p>{/if}
</section>

<section class="danger-zone">
  <h2>Export (plaintext CSV)</h2>
  <p class="warn" role="note">
    ⚠ A plaintext CSV contains all your passwords <strong>unencrypted</strong>. Anyone who reads the
    file can see every secret. Delete it as soon as you are done.
  </p>
  <form onsubmit={exportCsv}>
    <PasswordField id="csvpw" label="Re-enter master password" bind:value={csvPw} copyable={false} autocomplete="current-password" />
    <label class="ack">
      <input type="checkbox" bind:checked={csvAck} />
      I understand this file is unencrypted.
    </label>
    <button class="danger" type="submit" disabled={!csvPw}>Download plaintext CSV</button>
  </form>
  {#if csvMsg}<p role="alert">{csvMsg}</p>{/if}
</section>

<style>
  section {
    border-top: 1px solid var(--border);
    padding: 16px 0;
    max-width: 34rem;
  }
  .actions {
    display: flex;
    gap: 8px;
    margin-top: 12px;
    flex-wrap: wrap;
  }
  .muted {
    color: var(--muted);
  }
  .errs {
    color: var(--danger);
  }
  .warn {
    background: color-mix(in srgb, var(--danger) 12%, transparent);
    border: 1px solid var(--danger);
    border-radius: var(--radius);
    padding: 12px;
  }
  .ack {
    display: flex;
    gap: 8px;
    align-items: center;
    font-weight: 400;
  }
  .ack input {
    width: auto;
    min-height: auto;
  }
  button[type='submit'] {
    margin-top: 12px;
  }
</style>
