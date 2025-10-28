import { Container, getContainer } from "@cloudflare/containers";
export class MyContainer extends Container {
  defaultPort = 8080;
  envVars = { PORT: "8080" };
  sleepAfter = "10m";
}
export default {
  async fetch(req: Request, env: Env) {
    const c = getContainer(env.MY_CONTAINER, "singleton");
    await c.startAndWaitForPorts();
    return c.fetch(req);
  },
};
