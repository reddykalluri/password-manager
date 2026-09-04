// Native-messaging delegation to the desktop app (browser-extensions spec:
// standalone and delegated operation). Talks to the `vault-nmh` host, which is
// allowlisted on both ends by extension/app ID.

const HOST_NAME = 'au.com.rodoskosmos.vault';

/** One request/response round trip to the desktop host. Resolves `null` if the
 * desktop app / host is not installed, so the extension falls back to standalone. */
export function queryDesktop<T = unknown>(request: object): Promise<T | null> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (v: T | null) => {
      if (!settled) {
        settled = true;
        resolve(v);
      }
    };
    try {
      const port = chrome.runtime.connectNative(HOST_NAME);
      port.onMessage.addListener((msg) => {
        finish(msg as T);
        port.disconnect();
      });
      port.onDisconnect.addListener(() => finish(null));
      port.postMessage(request);
      // Guard against a host that never replies.
      setTimeout(() => finish(null), 2000);
    } catch {
      finish(null);
    }
  });
}

export async function desktopAvailable(): Promise<boolean> {
  const r = await queryDesktop<{ unlocked?: boolean }>({ type: 'ping' });
  return r !== null;
}

export async function desktopUnlockState(): Promise<boolean> {
  const r = await queryDesktop<{ unlocked?: boolean }>({ type: 'unlock_state' });
  return !!r?.unlocked;
}

export async function desktopCandidates(url: string): Promise<Array<Record<string, unknown>>> {
  const r = await queryDesktop<{ items?: Array<Record<string, unknown>> }>({
    type: 'get_candidates',
    url
  });
  return r?.items ?? [];
}

export async function desktopFill(id: string): Promise<Record<string, unknown> | null> {
  const r = await queryDesktop<{ item?: Record<string, unknown> }>({ type: 'request_fill', id });
  return r?.item ?? null;
}
