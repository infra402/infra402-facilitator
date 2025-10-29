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

    // Build environment variables object, filtering out undefined values
    const envVars: Record<string, string> = {
      PORT: env.PORT || "8080",
      HOST: env.HOST || "0.0.0.0",
      RUST_LOG: env.RUST_LOG || "info",
    };

    // Add optional environment variables if defined
    if (env.SIGNER_TYPE) envVars.SIGNER_TYPE = env.SIGNER_TYPE;
    if (env.EVM_PRIVATE_KEY) envVars.EVM_PRIVATE_KEY = env.EVM_PRIVATE_KEY;
    if (env.SOLANA_PRIVATE_KEY) envVars.SOLANA_PRIVATE_KEY = env.SOLANA_PRIVATE_KEY;
    if (env.RPC_URL_BASE_SEPOLIA) envVars.RPC_URL_BASE_SEPOLIA = env.RPC_URL_BASE_SEPOLIA;
    if (env.RPC_URL_BASE) envVars.RPC_URL_BASE = env.RPC_URL_BASE;
    if (env.RPC_URL_XDC) envVars.RPC_URL_XDC = env.RPC_URL_XDC;
    if (env.RPC_URL_AVALANCHE_FUJI) envVars.RPC_URL_AVALANCHE_FUJI = env.RPC_URL_AVALANCHE_FUJI;
    if (env.RPC_URL_AVALANCHE) envVars.RPC_URL_AVALANCHE = env.RPC_URL_AVALANCHE;
    if (env.RPC_URL_POLYGON_AMOY) envVars.RPC_URL_POLYGON_AMOY = env.RPC_URL_POLYGON_AMOY;
    if (env.RPC_URL_POLYGON) envVars.RPC_URL_POLYGON = env.RPC_URL_POLYGON;
    if (env.RPC_URL_SEI) envVars.RPC_URL_SEI = env.RPC_URL_SEI;
    if (env.RPC_URL_SEI_TESTNET) envVars.RPC_URL_SEI_TESTNET = env.RPC_URL_SEI_TESTNET;
    if (env.RPC_URL_BSC_TESTNET) envVars.RPC_URL_BSC_TESTNET = env.RPC_URL_BSC_TESTNET;
    if (env.RPC_URL_BSC) envVars.RPC_URL_BSC = env.RPC_URL_BSC;
    if (env.SOLANA_RPC_URL_MAINNET) envVars.SOLANA_RPC_URL_MAINNET = env.SOLANA_RPC_URL_MAINNET;
    if (env.SOLANA_RPC_URL_DEVNET) envVars.SOLANA_RPC_URL_DEVNET = env.SOLANA_RPC_URL_DEVNET;
    if (env.API_KEYS) envVars.API_KEYS = env.API_KEYS;
    if (env.ADMIN_API_KEY) envVars.ADMIN_API_KEY = env.ADMIN_API_KEY;
    if (env.CONFIG_FILE) envVars.CONFIG_FILE = env.CONFIG_FILE;
    if (env.OTEL_EXPORTER_OTLP_ENDPOINT) envVars.OTEL_EXPORTER_OTLP_ENDPOINT = env.OTEL_EXPORTER_OTLP_ENDPOINT;
    if (env.OTEL_EXPORTER_OTLP_HEADERS) envVars.OTEL_EXPORTER_OTLP_HEADERS = env.OTEL_EXPORTER_OTLP_HEADERS;
    if (env.OTEL_EXPORTER_OTLP_PROTOCOL) envVars.OTEL_EXPORTER_OTLP_PROTOCOL = env.OTEL_EXPORTER_OTLP_PROTOCOL;

    // Pass environment variables from Worker to Container
    await c.startAndWaitForPorts({
      startOptions: {
        envVars
      }
    });

    return c.fetch(req);
  },
};
