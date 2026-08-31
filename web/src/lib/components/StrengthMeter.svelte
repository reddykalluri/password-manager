<script lang="ts">
  import { session } from '$lib/session.svelte';

  let { password = '' }: { password?: string } = $props();

  // Text label accompanies the bar so colour is never the sole indicator.
  let s = $derived(session.ready ? session.rateStrength(password) : { score: 0, label: 'unknown', entropy_bits: 0 });
</script>

<div class="strength">
  <div class="bars" aria-hidden="true">
    {#each Array(5) as _, i (i)}
      <span class:filled={password.length > 0 && i <= s.score} data-score={s.score}></span>
    {/each}
  </div>
  <span class="label">Strength: <strong>{password.length ? s.label : '—'}</strong></span>
</div>

<style>
  .strength {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-top: 6px;
  }
  .bars {
    display: flex;
    gap: 3px;
  }
  .bars span {
    width: 26px;
    height: 6px;
    border-radius: 3px;
    background: var(--border);
  }
  .bars span.filled[data-score='0'],
  .bars span.filled[data-score='1'] {
    background: var(--danger);
  }
  .bars span.filled[data-score='2'] {
    background: #b8860b;
  }
  .bars span.filled[data-score='3'],
  .bars span.filled[data-score='4'] {
    background: var(--ok);
  }
  .label {
    font-size: 0.9rem;
    color: var(--muted);
  }
</style>
