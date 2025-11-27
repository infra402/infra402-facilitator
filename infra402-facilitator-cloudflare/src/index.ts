import { Container, getContainer } from "@cloudflare/containers";

export class MyContainer extends Container {
  defaultPort = 8080;
  requiredPorts = [8080];             // ensures this port must be up
  sleepAfter = "10m";

  override onStart() {
    console.log('Container successfully started');
  }

  override onStop() {
    console.log('Container successfully shut down');
  }

  override onError(error: unknown) {
    console.error('Container error:', error);
  }
}

// Keep only defined keys (all values must be strings)
const pickDefined = (o: Record<string, string | undefined>) =>
  Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined));

// Build environment variables from Worker env (secrets + vars)
function buildEnvVars(workerEnv: Env): Record<string, string> {
  return pickDefined({
    PORT: workerEnv.PORT ?? "8080",
    HOST: workerEnv.HOST ?? "0.0.0.0",
    RUST_LOG: workerEnv.RUST_LOG ?? "info",
    SIGNER_TYPE: workerEnv.SIGNER_TYPE,
    EVM_PRIVATE_KEY: workerEnv.EVM_PRIVATE_KEY,
    SOLANA_PRIVATE_KEY: workerEnv.SOLANA_PRIVATE_KEY,
    RPC_URL_BASE_SEPOLIA: workerEnv.RPC_URL_BASE_SEPOLIA,
    RPC_URL_BASE: workerEnv.RPC_URL_BASE,
    RPC_URL_XDC: workerEnv.RPC_URL_XDC,
    RPC_URL_AVALANCHE_FUJI: workerEnv.RPC_URL_AVALANCHE_FUJI,
    RPC_URL_AVALANCHE: workerEnv.RPC_URL_AVALANCHE,
    RPC_URL_POLYGON_AMOY: workerEnv.RPC_URL_POLYGON_AMOY,
    RPC_URL_POLYGON: workerEnv.RPC_URL_POLYGON,
    RPC_URL_SEI: workerEnv.RPC_URL_SEI,
    RPC_URL_SEI_TESTNET: workerEnv.RPC_URL_SEI_TESTNET,
    RPC_URL_BSC_TESTNET: workerEnv.RPC_URL_BSC_TESTNET,
    RPC_URL_BSC: workerEnv.RPC_URL_BSC,
    SOLANA_RPC_URL_MAINNET: workerEnv.SOLANA_RPC_URL_MAINNET,
    SOLANA_RPC_URL_DEVNET: workerEnv.SOLANA_RPC_URL_DEVNET,
    API_KEYS: workerEnv.API_KEYS,
    ADMIN_API_KEY: workerEnv.ADMIN_API_KEY,
    CONFIG_FILE: workerEnv.CONFIG_FILE ?? "/app/config.toml",
    TOKENS_FILE: workerEnv.TOKENS_FILE ?? "/app/tokens.toml",
    HOOKS_FILE: workerEnv.HOOKS_FILE ?? "/app/hooks.toml",
    OTEL_EXPORTER_OTLP_ENDPOINT: workerEnv.OTEL_EXPORTER_OTLP_ENDPOINT,
    OTEL_EXPORTER_OTLP_HEADERS: workerEnv.OTEL_EXPORTER_OTLP_HEADERS,
    OTEL_EXPORTER_OTLP_PROTOCOL: workerEnv.OTEL_EXPORTER_OTLP_PROTOCOL,
    UP_DOWN_402_RECIPIENT_BSC_TESTNET: workerEnv.UP_DOWN_402_RECIPIENT_BSC_TESTNET,
    HOOK_UP_DOWN_402_CALLBACK_BSC_TESTNET_CONTRACT: workerEnv.HOOK_UP_DOWN_402_CALLBACK_BSC_TESTNET_CONTRACT,
  });
}

export default {
  async fetch(req: Request, env: Env) {
    const c = getContainer(env.MY_CONTAINER, "singleton");

    await c.startAndWaitForPorts({
      startOptions: {
        envVars: buildEnvVars(env)
      }
    });

    return c.fetch(req);
  },

  async scheduled(controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    console.log('Running scheduled keep-alive ping at', new Date(controller.scheduledTime));

    try {
      const c = getContainer(env.MY_CONTAINER, "singleton");

      // Start container if not running
      await c.startAndWaitForPorts({
        startOptions: {
          envVars: buildEnvVars(env)
        }
      });

      // Ping the health endpoint to keep container alive
      const healthCheck = await c.fetch(new Request('http://container/health', {
        method: 'GET'
      }));

      if (healthCheck.ok) {
        console.log('Keep-alive ping successful');
      } else {
        console.warn('Keep-alive ping returned non-OK status:', healthCheck.status);
      }
    } catch (error) {
      console.error('Keep-alive ping failed:', error);
      // Don't throw - we don't want cron to fail
    }
  },
};
