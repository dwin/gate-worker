export type FetchHandler = (request: Request) => Promise<Response> | Response;

/**
 * A `fetch` that dispatches by origin to in-memory fakes and fails any request
 * to an unknown origin, so tests can never reach the network.
 */
export function createFetchRouter(routes: Readonly<Record<string, FetchHandler>>) {
  const calls: Request[] = [];
  const fetchImpl = async (
    input: Request | string | URL,
    init?: RequestInit,
  ): Promise<Response> => {
    const request = new Request(input, init);
    calls.push(request.clone());
    const handler = routes[new URL(request.url).origin];
    if (!handler) {
      throw new TypeError(`unexpected outbound request in test: ${request.method} ${request.url}`);
    }
    return handler(request);
  };
  return { fetch: fetchImpl, calls };
}
