<script lang="ts">
  import { session } from '$lib/session.svelte';
  import { goto } from '$app/navigation';

  $effect(() => {
    if (session.unlocked) goto('/vault');
  });
</script>

<section class="landing">
  <h1>Your self-hosted vault</h1>
  <p>All encryption happens in your browser. Your master password never leaves this device.</p>
  <div class="actions">
    <a class="btn primary" href="/unlock">Sign in</a>
    <a class="btn" href="/enroll">Create account</a>
  </div>
</section>

<style>
  .landing {
    max-width: 32rem;
    margin: 10vh auto 0;
    text-align: center;
  }
  .actions {
    display: flex;
    gap: 12px;
    justify-content: center;
    margin-top: 24px;
    flex-wrap: wrap;
  }
  .btn {
    display: inline-flex;
    align-items: center;
    text-decoration: none;
  }
</style>
