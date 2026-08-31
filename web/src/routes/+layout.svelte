<script lang="ts">
  import '../app.css';
  import { onMount } from 'svelte';
  import { session } from '$lib/session.svelte';
  import { goto } from '$app/navigation';

  let { children } = $props();

  onMount(() => {
    session.init();
  });

  function onActivity() {
    session.touch();
  }

  async function lock() {
    session.lock();
    await goto('/unlock');
  }
</script>

<svelte:window onpointerdown={onActivity} onkeydown={onActivity} />

<a class="skip-link" href="#main">Skip to main content</a>

<!-- Polite live region for sync status, clipboard, lock announcements. -->
<div aria-live="polite" role="status" class="visually-hidden">{session.announce}</div>

<header class="topbar">
  <a class="brand" href="/">Vault</a>
  {#if session.unlocked}
    <nav aria-label="Primary">
      <a href="/vault">Items</a>
      <a href="/import-export">Import / Export</a>
      <a href="/settings">Settings</a>
    </nav>
    <button class="primary" onclick={lock}>Lock</button>
  {/if}
</header>

<main id="main" tabindex="-1">
  {@render children()}
</main>

<style>
  .topbar {
    display: flex;
    align-items: center;
    gap: 16px;
    padding: 8px 16px;
    border-bottom: 1px solid var(--border);
    flex-wrap: wrap;
  }
  .brand {
    font-weight: 700;
    font-size: 1.1rem;
    text-decoration: none;
    color: var(--fg);
  }
  nav {
    display: flex;
    gap: 12px;
    margin-inline-start: auto;
  }
  nav a {
    padding: 8px;
  }
  main {
    padding: 16px;
    max-width: 1100px;
    margin: 0 auto;
  }
  @media (max-width: 520px) {
    nav {
      width: 100%;
      margin-inline-start: 0;
    }
  }
</style>
