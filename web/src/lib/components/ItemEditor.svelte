<script lang="ts">
  import type { ItemContent, Uri } from '$lib/types';
  import PasswordField from './PasswordField.svelte';
  import Generator from './Generator.svelte';
  import { session } from '$lib/session.svelte';

  let {
    content,
    onsave,
    oncancel
  }: {
    content: ItemContent;
    onsave: (c: ItemContent) => void;
    oncancel: () => void;
  } = $props();

  // Editable working copy.
  let draft = $state<ItemContent>(structuredClone($state.snapshot(content)) as ItemContent);
  let tagsText = $state(draft.tags.join(', '));
  let showGenerator = $state(false);

  function addUri() {
    if (draft.data.type === 'login') draft.data.uris.push({ value: '', match_rule: 'base_domain' });
  }
  function removeUri(i: number) {
    if (draft.data.type === 'login') draft.data.uris.splice(i, 1);
  }

  function save() {
    draft.tags = tagsText
      .split(',')
      .map((t) => t.trim())
      .filter(Boolean);
    onsave($state.snapshot(draft) as ItemContent);
  }

  const matchRules = [
    ['base_domain', 'Base domain'],
    ['host', 'Host'],
    ['exact', 'Exact URL'],
    ['never', 'Never']
  ] as const;
</script>

<form class="editor" onsubmit={(e) => { e.preventDefault(); save(); }}>
  <label for="title">Title</label>
  <input id="title" bind:value={draft.title} required />

  {#if draft.data.type === 'login'}
    <label for="user">Username</label>
    <div class="row">
      <input id="user" bind:value={draft.data.username} autocomplete="off" />
      <button type="button" onclick={() => session.copySecret(draft.data.type === 'login' ? draft.data.username : '', 'Username')}>
        Copy
      </button>
    </div>

    <PasswordField id="pass" label="Password" bind:value={draft.data.password} autocomplete="off" />
    <button type="button" class="link" aria-expanded={showGenerator} onclick={() => (showGenerator = !showGenerator)}>
      {showGenerator ? 'Hide generator' : 'Generate password'}
    </button>
    {#if showGenerator}
      <Generator
        onuse={(v) => {
          if (draft.data.type === 'login') draft.data.password = v;
          showGenerator = false;
        }}
      />
    {/if}

    <fieldset class="uris">
      <legend>Website URIs</legend>
      {#each draft.data.uris as uri, i (i)}
        <div class="uri-row">
          <input aria-label="URI {i + 1}" bind:value={uri.value} placeholder="https://example.com" />
          <select aria-label="Match rule for URI {i + 1}" bind:value={uri.match_rule}>
            {#each matchRules as [val, name] (val)}
              <option value={val}>{name}</option>
            {/each}
          </select>
          <button type="button" class="danger" onclick={() => removeUri(i)} aria-label="Remove URI {i + 1}">
            Remove
          </button>
        </div>
      {/each}
      <button type="button" onclick={addUri}>Add URI</button>
    </fieldset>

    <label for="totp">TOTP secret <span class="muted">(otpauth URI or base32)</span></label>
    <input id="totp" bind:value={draft.data.totp} autocomplete="off" />
  {/if}

  <label for="notes">Notes</label>
  <textarea id="notes" rows="4" bind:value={draft.notes}></textarea>

  <label for="folder">Folder</label>
  <input id="folder" bind:value={draft.folder} autocomplete="off" />

  <label for="tags">Tags <span class="muted">(comma-separated)</span></label>
  <input id="tags" bind:value={tagsText} autocomplete="off" />

  <label class="fav">
    <input type="checkbox" bind:checked={draft.favorite} /> Favourite
  </label>

  <div class="actions">
    <button type="submit" class="primary">Save</button>
    <button type="button" onclick={oncancel}>Cancel</button>
  </div>
</form>

<style>
  .row {
    display: flex;
    gap: 8px;
  }
  .row input {
    flex: 1;
  }
  .link {
    background: none;
    border: none;
    color: var(--accent);
    text-decoration: underline;
    padding: 8px 0;
    min-height: auto;
  }
  .uris {
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 8px 12px;
    margin-top: 12px;
  }
  .uri-row {
    display: flex;
    gap: 8px;
    margin-bottom: 8px;
    flex-wrap: wrap;
  }
  .uri-row input {
    flex: 2;
    min-width: 12rem;
  }
  .uri-row select {
    flex: 1;
    min-width: 8rem;
  }
  .muted {
    color: var(--muted);
    font-weight: 400;
  }
  .fav {
    display: flex;
    gap: 8px;
    align-items: center;
    font-weight: 400;
  }
  .fav input {
    width: auto;
    min-height: auto;
  }
  .actions {
    display: flex;
    gap: 8px;
    margin-top: 16px;
  }
</style>
