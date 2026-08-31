<script lang="ts">
  import { goto } from '$app/navigation';
  import { session } from '$lib/session.svelte';
  import { ApiError } from '$lib/api';
  import PasswordField from '$lib/components/PasswordField.svelte';

  let username = $state('');
  let password = $state('');
  let totpCode = $state('');
  let needTotp = $state(false);
  let busy = $state(false);
  let error = $state<string | null>(null);

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    error = null;
    busy = true;
    try {
      await session.unlock({ username, password, totpCode: needTotp ? totpCode : undefined });
      await goto('/vault');
    } catch (err) {
      if (err instanceof ApiError && err.code === 'second_factor_required') {
        needTotp = true;
        error = 'Enter your authenticator code to continue.';
      } else if (err instanceof ApiError && err.status === 401) {
        error = 'Incorrect username or master password.';
      } else {
        error = (err as Error).message;
      }
    } finally {
      busy = false;
    }
  }
</script>

<section class="wrap">
  <h1>Sign in</h1>
  <form onsubmit={submit}>
    <label for="u">Username</label>
    <input id="u" bind:value={username} autocomplete="username" required />

    <PasswordField id="pw" label="Master password" bind:value={password} copyable={false} autocomplete="current-password" />

    {#if needTotp}
      <label for="totp">Authenticator code</label>
      <input
        id="totp"
        bind:value={totpCode}
        inputmode="numeric"
        autocomplete="one-time-code"
        pattern="[0-9]*"
        maxlength="6"
      />
    {/if}

    {#if error}<p class="err" role="alert">{error}</p>{/if}

    <button class="primary" type="submit" disabled={busy}>
      {busy ? 'Unlocking…' : 'Unlock'}
    </button>
  </form>
  <p><a href="/enroll">Create an account</a></p>
</section>

<style>
  .wrap {
    max-width: 26rem;
    margin: 6vh auto 0;
  }
  .err {
    color: var(--danger);
  }
  button[type='submit'] {
    margin-top: 16px;
  }
</style>
