<script lang="ts">
  import { onMount } from 'svelte';
  import { session } from '$lib/session.svelte';

  // Quick-search window (desktop tray / global shortcut). Shares the desktop's
  // native vault; never renders secrets while locked.
  let attached = $state(false);

  onMount(async () => {
    await session.init();
    attached = await session.attach();
  });

  async function copyField(id: string, field: 'username' | 'password') {
    const c = await session.getItem(id);
    if (c.data.type === 'login') {
      session.copySecret(field === 'username' ? c.data.username : c.data.password, field);
    }
  }
</script>

<section class="quick">
  {#if attached}
    <label for="q" class="visually-hidden">Search</label>
    <input
      id="q"
      type="search"
      placeholder="Search your vault"
      value={session.query}
      oninput={(e) => session.setQuery((e.target as HTMLInputElement).value)}
    />
    <ul>
      {#each session.items.slice(0, 20) as item (item.id)}
        <li>
          <span class="t">{item.title}<span class="u">{item.username}</span></span>
          <span class="acts">
            {#if item.kind === 'login'}
              <button onclick={() => copyField(item.id, 'username')}>User</button>
              <button onclick={() => copyField(item.id, 'password')}>Pass</button>
            {/if}
          </span>
        </li>
      {/each}
    </ul>
  {:else}
    <p class="locked">Vault is locked. Open the main window to unlock.</p>
  {/if}
</section>

<style>
  .quick {
    padding: 12px;
  }
  ul {
    list-style: none;
    margin: 8px 0 0;
    padding: 0;
    max-height: 320px;
    overflow: auto;
  }
  li {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 8px;
    padding: 6px 8px;
    border-bottom: 1px solid var(--border);
  }
  .t {
    display: flex;
    flex-direction: column;
  }
  .u {
    color: var(--muted);
    font-size: 0.8rem;
  }
  .acts {
    display: flex;
    gap: 6px;
  }
  .locked {
    color: var(--muted);
    text-align: center;
    padding: 24px;
  }
</style>
