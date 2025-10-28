import { Container, getContainer } from "@cloudflare/containers";
export class MyContainer extends Container {
  defaultPort = 8080;
  envVars = { PORT: "8080" };
  requiredPorts = [8080];             // ensures this port must be up
  sleepAfter = "10m";

  override onStart() {
    console.log('Container successfully started');
  }

  override onStop() {
    console.log('Container successfully shut down');
  }

  override onError(error: unknown) {
    console.log('Container error:', error);
  }
}

export default {
  async fetch(req: Request, env: Env) {
    const c = getContainer(env.MY_CONTAINER, "singleton");
    await c.startAndWaitForPorts();
    return c.fetch(req);
  },
};
