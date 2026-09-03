<script lang="ts">
  import { goto } from '$app/navigation';
  import { session } from '$lib/session.svelte';
  import { ApiError } from '$lib/api';
  import StrengthMeter from '$lib/components/StrengthMeter.svelte';
  import PasswordField from '$lib/components/PasswordField.svelte';

  let username = $state('');
  let inviteCode = $state('');
  let password = $state('');
  let confirm = $state('');
  let busy = $state(false);
  let error = $state<string | null>(null);
  let acknowledged = $state(false);

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    error = null;
    if (password !== confirm) {
      error = 'Passwords do not match.';
      return;
    }
    if (password.length < 8) {
      error = 'Master password must be at least 8 characters.';
      return;
    }
    busy = true;
    try {
      const paramsJson = await session.negotiateParams();
      await session.enroll({ username, password, inviteCode, paramsJson });
      // Recovery code is shown before entering the vault.
      if (!session.recoveryCode) await goto('/vault');
    } catch (err) {
      if (err instanceof ApiError && err.code === 'registration_closed') {
        error = 'Registration is closed. You need an invite code.';
      } else {
        error = (err as Error).message;
      }
    } finally {
      busy = false;
    }
  }

  async function done() {
    session.recoveryCode = null;
    await goto('/vault');
  }
</script>

<section class="wrap">
  {#if session.recoveryCode}
    <h1>Save your recovery code</h1>
    <p>
      This code can restore access if you forget your master password. It is shown
      <strong>once</strong>. There is no server-side reset — lose both and your data is
      unrecoverable.
    </p>
    <output class="code">{session.recoveryCode}</output>
    <div class="actions">
      <button type="button" onclick={() => session.copySecret(session.recoveryCode ?? '', 'Recovery code')}>
        Copy
      </button>
    </div>
    <label class="ack">
      <input type="checkbox" bind:checked={acknowledged} />
      I have saved my recovery code somewhere safe.
    </label>
    <button class="primary" disabled={!acknowledged} onclick={done}>Continue to vault</button>
  {:else}
    <h1>Create your account</h1>
    <form onsubmit={submit}>
      <label for="u">Username</label>
      <input id="u" bind:value={username} autocomplete="username" required />

      <label for="invite">Invite code <span class="muted">(if required)</span></label>
      <input id="invite" bind:value={inviteCode} autocomplete="off" />

      <PasswordField id="pw" label="Master password" bind:value={password} copyable={false} autocomplete="new-password" />
      <StrengthMeter {password} />

      <PasswordField id="pw2" label="Confirm master password" bind:value={confirm} copyable={false} autocomplete="new-password" />

      {#if error}<p class="err" role="alert">{error}</p>{/if}

      <button class="primary" type="submit" disabled={busy}>
        {busy ? 'Creating…' : 'Create account'}
      </button>
    </form>
    <p><a href="/unlock">Already have an account? Sign in</a></p>
  {/if}
</section>

<style>
  .wrap {
    max-width: 30rem;
    margin: 4vh auto 0;
  }
  .muted {
    color: var(--muted);
    font-weight: 400;
  }
  .err {
    color: var(--danger);
  }
  .code {
    display: block;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 1.2rem;
    letter-spacing: 0.05em;
    padding: 16px;
    border: 2px dashed var(--accent);
    border-radius: var(--radius);
    text-align: center;
    margin: 16px 0;
    word-break: break-all;
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
  .actions {
    display: flex;
    gap: 8px;
  }
  button[type='submit'],
  .primary {
    margin-top: 16px;
  }
</style>
