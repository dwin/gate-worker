/**
 * The runner capabilities the action uses. Production wires these to
 * @actions/core; tests supply fakes, so the logic is tested without mocking modules.
 */
export interface ActionIO {
  getInput(name: string): string;
  getIDToken(audience: string): Promise<string>;
  setSecret(value: string): void;
  setOutput(name: string, value: string): void;
  saveState(name: string, value: string): void;
  getState(name: string): string;
  setFailed(message: string): void;
  info(message: string): void;
  warning(message: string): void;
}

export type Fetch = (input: string, init?: RequestInit) => Promise<Response>;
export type Sleep = (ms: number) => Promise<void>;

export const sleep: Sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
