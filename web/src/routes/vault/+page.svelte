<script lang="ts">
  import { goto } from '$app/navigation';
  import { session } from '$lib/session.svelte';
  import { newContent, type ItemContent } from '$lib/types';
  import ItemEditor from '$lib/components/ItemEditor.svelte';
  import PasswordField from '$lib/components/PasswordField.svelte';

  let selectedId = $state<string | null>(null);
  let editing = $state(false);
  let draft = $state<ItemContent | null>(null);
  let showHistory = $state(false);

  // Route guard: must be unlocked.
  $effect(() => {
    if (session.ready && !session.unlocked) goto('/unlock');
  });

  let selected = $derived(selectedId && session.unlocked ? session.getItem(selectedId) : null);
  let history = $derived(
    selectedId && showHistory ? session.history(selectedId) : []
  );

  function select(id: string) {
    selectedId = id;
    editing = false;
    showHistory = false;
  }

  function startCreate() {
    draft = newContent('login', '');
    editing = true;
    selectedId = null;
  }

  function startEdit() {
    if (!selectedId) return;
    draft = session.getItem(selectedId);
    editing = true;
  }

  async function save(c: ItemContent) {
    if (selectedId && !isNew) {
      await session.updateItem(selectedId, c);
    } else {
      selectedId = await session.createItem(c);
    }
    editing = false;
    draft = null;
  }

  let isNew = $derived(editing && !selectedId);

  async function bin() {
    if (!selectedId) return;
    await session.moveToBin(selectedId);
    selectedId = null;
  }

  async function restoreRev(i: number) {
    if (!selectedId) return;
    await session.restoreRevision(selectedId, i);
    showHistory = false;
  }
</script>

<div class="vault" class:has-selection={selectedId || editing}>
  <section class="list" aria-label="Items">
    <div class="list-head">
      <label for="search" class="visually-hidden">Search items</label>
      <input
        id="search"
        type="search"
        placeholder="Search"
        value={session.query}
        oninput={(e) => session.setQuery((e.target as HTMLInputElement).value)}
      />
      <button class="primary" onclick={startCreate}>New</button>
    </div>
    {#if session.items.length === 0}
      <p class="empty">No items{session.query ? ' match your search' : ' yet'}.</p>
    {:else}
      <ul>
        {#each session.items as item (item.id)}
          <li>
            <button class="item" aria-current={item.id === selectedId} onclick={() => select(item.id)}>
              <span class="title">{item.favorite ? '★ ' : ''}{item.title}</span>
              {#if item.username}<span class="sub">{item.username}</span>{/if}
            </button>
          </li>
        {/each}
      </ul>
    {/if}
  </section>

  <section class="detail" aria-label="Item detail">
    <button class="back" onclick={() => { selectedId = null; editing = false; }}>← Back to list</button>

    {#if editing && draft}
      <h2>{isNew ? 'New item' : 'Edit item'}</h2>
      <ItemEditor content={draft} onsave={save} oncancel={() => { editing = false; draft = null; }} />
    {:else if selected}
      <div class="detail-head">
        <h2>{selected.title}</h2>
        <div class="detail-actions">
          <button onclick={startEdit}>Edit</button>
          <button class="danger" onclick={bin}>Move to bin</button>
        </div>
      </div>

      {#if selected.data.type === 'login'}
        {#if selected.data.username}
          <label for="d-user">Username</label>
          <div class="copyrow">
            <input id="d-user" readonly value={selected.data.username} />
            <button onclick={() => session.copySecret(selected.data.type === 'login' ? selected.data.username : '', 'Username')}>Copy</button>
          </div>
        {/if}
        {#if selected.data.password}
          <PasswordField id="d-pass" label="Password" value={selected.data.password} />
        {/if}
        {#if selected.data.uris.length}
          <h3>Websites</h3>
          <ul class="uris">
            {#each selected.data.uris as u (u.value)}
              <li><a href={u.value} target="_blank" rel="noopener noreferrer">{u.value}</a> <span class="muted">({u.match_rule})</span></li>
            {/each}
          </ul>
        {/if}
        {#if selected.data.totp}
          <label for="d-totp">TOTP secret</label>
          <div class="copyrow">
            <input id="d-totp" readonly type="password" value={selected.data.totp} />
            <button onclick={() => session.copySecret(selected.data.type === 'login' ? (selected.data.totp ?? '') : '', 'TOTP secret')}>Copy</button>
          </div>
        {/if}
      {/if}

      {#if selected.notes}
        <h3>Notes</h3>
        <p class="notes">{selected.notes}</p>
      {/if}
      {#if selected.tags.length}
        <p class="tags">{#each selected.tags as t (t)}<span class="tag">{t}</span>{/each}</p>
      {/if}

      <button class="link" aria-expanded={showHistory} onclick={() => (showHistory = !showHistory)}>
        {showHistory ? 'Hide history' : 'Show history'}
      </button>
      {#if showHistory}
        {#if history.length === 0}
          <p class="muted">No previous revisions.</p>
        {:else}
          <ul class="history">
            {#each history as rev, i (rev.modified_at + i)}
              <li>
                <span>{new Date(rev.modified_at).toLocaleString()} — {rev.content.title}</span>
                <button onclick={() => restoreRev(i)}>Restore</button>
              </li>
            {/each}
          </ul>
        {/if}
      {/if}
    {:else}
      <p class="placeholder">Select an item, or create a new one.</p>
    {/if}
  </section>
</div>

<style>
  .vault {
    display: grid;
    grid-template-columns: minmax(220px, 320px) 1fr;
    gap: 16px;
    align-items: start;
  }
  .list-head {
    display: flex;
    gap: 8px;
    margin-bottom: 8px;
  }
  .list ul {
    list-style: none;
    margin: 0;
    padding: 0;
  }
  .item {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    width: 100%;
    text-align: start;
    gap: 2px;
    padding: 10px 12px;
    border: 1px solid transparent;
    border-bottom-color: var(--border);
    border-radius: 0;
    background: none;
  }
  .item[aria-current='true'] {
    background: var(--surface);
    border-color: var(--accent);
    border-radius: var(--radius);
  }
  .item .sub {
    color: var(--muted);
    font-size: 0.85rem;
  }
  .detail {
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 16px;
    min-height: 60vh;
  }
  .detail-head {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
  }
  .detail-actions {
    display: flex;
    gap: 8px;
  }
  .copyrow {
    display: flex;
    gap: 8px;
  }
  .copyrow input {
    flex: 1;
  }
  .uris {
    padding-left: 1.2em;
  }
  .tag {
    display: inline-block;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 999px;
    padding: 2px 10px;
    margin-right: 6px;
    font-size: 0.85rem;
  }
  .history {
    list-style: none;
    padding: 0;
  }
  .history li {
    display: flex;
    justify-content: space-between;
    gap: 12px;
    align-items: center;
    padding: 6px 0;
    border-bottom: 1px solid var(--border);
  }
  .link {
    background: none;
    border: none;
    color: var(--accent);
    text-decoration: underline;
    padding: 8px 0;
    min-height: auto;
  }
  .muted {
    color: var(--muted);
  }
  .back {
    display: none;
    margin-bottom: 8px;
  }
  /* Single-column on narrow screens: list OR detail. */
  @media (max-width: 767px) {
    .vault {
      grid-template-columns: 1fr;
    }
    .vault.has-selection .list {
      display: none;
    }
    .vault:not(.has-selection) .detail {
      display: none;
    }
    .back {
      display: inline-flex;
    }
  }
</style>
