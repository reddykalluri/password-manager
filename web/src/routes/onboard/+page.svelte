<script lang="ts">
  import { goto } from '$app/navigation';
  import { api } from '$lib/api';

  let url = $state('https://');
  let error = $state<string | null>(null);

  async function save(e: SubmitEvent) {
    e.preventDefault();
    error = null;
    try {
      const parsed = new URL(url);
      if (!parsed.protocol.startsWith('http')) throw new Error('bad');
    } catch {
      error = 'Enter a valid URL, e.g. https://vault.example.com';
      return;
    }
    api.setInstance(url);
    await goto('/unlock');
  }
</script>

<section class="wrap">
  <h1>Connect to your instance</h1>
  <p>Enter the address of your self-hosted vault server. All encryption stays on this device.</p>
  <form onsubmit={save}>
    <label for="url">Instance URL</label>
    <input id="url" bind:value={url} type="url" inputmode="url" autocomplete="url" required />
    {#if error}<p class="err" role="alert">{error}</p>{/if}
    <button class="primary" type="submit">Continue</button>
  </form>
</section>

<style>
  .wrap {
    max-width: 28rem;
    margin: 8vh auto 0;
  }
  .err {
    color: var(--danger);
  }
  button {
    margin-top: 16px;
  }
</style>
