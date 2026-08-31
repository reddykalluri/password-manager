<script lang="ts">
  import type { HTMLInputAttributes } from 'svelte/elements';
  import { session } from '$lib/session.svelte';

  let {
    value = $bindable(''),
    label,
    id,
    copyable = true,
    autocomplete = 'off'
  }: {
    value?: string;
    label: string;
    id: string;
    copyable?: boolean;
    autocomplete?: HTMLInputAttributes['autocomplete'];
  } = $props();

  let revealed = $state(false);
</script>

<label for={id}>{label}</label>
<div class="row">
  <input
    {id}
    type={revealed ? 'text' : 'password'}
    bind:value
    {autocomplete}
    spellcheck="false"
    autocapitalize="off"
  />
  <button
    type="button"
    aria-pressed={revealed}
    onclick={() => (revealed = !revealed)}
    title={revealed ? 'Hide' : 'Reveal'}
  >
    {revealed ? 'Hide' : 'Show'}
  </button>
  {#if copyable}
    <button type="button" onclick={() => session.copySecret(value, label)} title="Copy {label}">
      Copy
    </button>
  {/if}
</div>

<style>
  .row {
    display: flex;
    gap: 8px;
  }
  .row input {
    flex: 1;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  }
</style>
