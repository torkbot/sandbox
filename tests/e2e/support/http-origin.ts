export interface TestHttpsOrigin {
  readonly url: string;
  close(): Promise<void>;
}

export async function startTestHttpsOrigin(_input: {
  respond(request: {
    readonly headers: Record<string, string>;
  }): {
    readonly status: number;
    readonly headers?: Record<string, string>;
    readonly body?: string;
  };
}): Promise<TestHttpsOrigin> {
  throw new Error("test HTTPS origin is not implemented yet");
}
