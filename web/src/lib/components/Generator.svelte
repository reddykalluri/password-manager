<script lang="ts">
  import { session } from '$lib/session.svelte';
  import StrengthMeter from './StrengthMeter.svelte';

  let { onuse }: { onuse?: (value: string) => void } = $props();

  let mode = $state<'password' | 'passphrase'>('password');
  let length = $state(20);
  let lowercase = $state(true);
  let uppercase = $state(true);
  let digits = $state(true);
  let symbols = $state(true);
  let excludeAmbiguous = $state(false);
  let words = $state(4);
  let separator = $state('-');
  let capitalize = $state(false);
  let includeNumber = $state(false);
  let value = $state('');
  let genError = $state<string | null>(null);

  function generate() {
    genError = null;
    try {
      if (mode === 'password') {
        value = session.generatePassword({
          length,
          lowercase,
          uppercase,
          digits,
          symbols,
          exclude_ambiguous: excludeAmbiguous
        });
      } else {
        value = session.generatePassphrase({
          words,
          separator,
          capitalize,
          include_number: includeNumber
        });
      }
    } catch (e) {
      genError = (e as Error).message;
    }
  }

  $effect(() => {
    if (session.ready && !value) generate();
  });
</script>

<fieldset class="gen">
  <legend>Generator</legend>

  <div role="radiogroup" aria-label="Type" class="tabs">
    <button type="button" aria-pressed={mode === 'password'} onclick={() => (mode = 'password')}>
      Password
    </button>
    <button type="button" aria-pressed={mode === 'passphrase'} onclick={() => (mode = 'passphrase')}>
      Passphrase
    </button>
  </div>

  {#if mode === 'password'}
    <label for="gen-length">Length: {length}</label>
    <input id="gen-length" type="range" min="8" max="128" bind:value={length} onchange={generate} />
    <div class="checks">
      <label><input type="checkbox" bind:checked={lowercase} onchange={generate} /> a–z</label>
      <label><input type="checkbox" bind:checked={uppercase} onchange={generate} /> A–Z</label>
      <label><input type="checkbox" bind:checked={digits} onchange={generate} /> 0–9</label>
      <label><input type="checkbox" bind:checked={symbols} onchange={generate} /> symbols</label>
      <label
        ><input type="checkbox" bind:checked={excludeAmbiguous} onchange={generate} /> no ambiguous</label
      >
    </div>
  {:else}
    <label for="gen-words">Words: {words}</label>
    <input id="gen-words" type="range" min="3" max="10" bind:value={words} onchange={generate} />
    <label for="gen-sep">Separator</label>
    <input id="gen-sep" bind:value={separator} maxlength="3" onchange={generate} />
    <div class="checks">
      <label><input type="checkbox" bind:checked={capitalize} onchange={generate} /> Capitalize</label>
      <label
        ><input type="checkbox" bind:checked={includeNumber} onchange={generate} /> Include number</label
      >
    </div>
  {/if}

  <label for="gen-out">Generated</label>
  <output id="gen-out" class="out">{value}</output>
  <StrengthMeter password={value} />

  {#if genError}<p class="err" role="alert">{genError}</p>{/if}

  <div class="actions">
    <button type="button" onclick={generate}>Regenerate</button>
    <button type="button" onclick={() => session.copySecret(value, 'Generated password')}>Copy</button>
    {#if onuse}
      <button type="button" class="primary" onclick={() => onuse?.(value)}>Use</button>
    {/if}
  </div>
</fieldset>

<style>
  .gen {
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 12px 16px;
  }
  .tabs {
    display: flex;
    gap: 8px;
    margin-bottom: 8px;
  }
  .tabs button[aria-pressed='true'] {
    background: var(--accent);
    color: var(--accent-fg);
  }
  .checks {
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
    margin-top: 8px;
  }
  .checks label {
    display: flex;
    align-items: center;
    gap: 6px;
    font-weight: 400;
    margin: 0;
  }
  .checks input {
    width: auto;
    min-height: auto;
  }
  .out {
    display: block;
    padding: 10px 12px;
    border: 1px dashed var(--border);
    border-radius: var(--radius);
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    word-break: break-all;
    min-height: 44px;
  }
  .actions {
    display: flex;
    gap: 8px;
    margin-top: 12px;
    flex-wrap: wrap;
  }
  .err {
    color: var(--danger);
  }
</style>
