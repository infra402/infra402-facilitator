# Deployment Guide

Production deployment guide for the infra402 facilitator with Docker, Kubernetes, and reverse proxy configurations.

## Production Checklist

Before deploying to production, complete these items:

### Security
- ✅ Enable API key authentication (`API_KEYS`)
- ✅ Set admin key (`ADMIN_API_KEY`)
- ✅ Restrict CORS origins in `config.toml`
- ✅ Enable rate limiting
- ✅ Configure IP filtering (if needed)
- ✅ Use HTTPS (reverse proxy or load balancer)
- ✅ Store private keys in secret manager (AWS/GCP/Vault)

### Configuration
- ✅ Set appropriate rate limits for expected traffic
- ✅ Configure per-network transaction timeouts
- ✅ Enable batch settlement for high throughput
- ✅ Configure multiple facilitator wallets

### Monitoring
- ✅ Enable OpenTelemetry export
- ✅ Set up log aggregation
- ✅ Configure alerting for errors and low balances
- ✅ Set up uptime monitoring
- ✅ Monitor wallet gas balances

### Infrastructure
- ✅ Use dedicated RPC providers (Alchemy, Infura, etc.)
- ✅ Deploy behind reverse proxy (Nginx, Caddy, Cloudflare)
- ✅ Configure health checks
- ✅ Set up auto-restart on failure
- ✅ Plan for zero-downtime deployments

## Docker Deployment

### Build Image

```bash
# Build from source
docker build -t infra402-facilitator:latest .

# Or pull from registry (when available)
docker pull ghcr.io/infra402/facilitator:latest
```

### Run Container

```bash
docker run -d \
  --name facilitator \
  -p 8080:8080 \
  --env-file .env \
  -v $(pwd)/config.toml:/app/config.toml:ro \
  --restart unless-stopped \
  infra402-facilitator:latest
```

### Docker Compose

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  facilitator:
    image: infra402-facilitator:latest
    container_name: facilitator
    ports:
      - "8080:8080"
    env_file:
      - .env
    volumes:
      - ./config.toml:/app/config.toml:ro
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
```

Start:
```bash
docker-compose up -d
```

View logs:
```bash
docker-compose logs -f facilitator
```

Stop:
```bash
docker-compose down
```

## Kubernetes Deployment

### Deployment Manifest

Create `deployment.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: facilitator
  labels:
    app: facilitator
spec:
  replicas: 2
  selector:
    matchLabels:
      app: facilitator
  template:
    metadata:
      labels:
        app: facilitator
    spec:
      containers:
      - name: facilitator
        image: infra402-facilitator:latest
        ports:
        - containerPort: 8080
          name: http
        env:
        - name: HOST
          value: "0.0.0.0"
        - name: PORT
          value: "8080"
        - name: EVM_PRIVATE_KEY
          valueFrom:
            secretKeyRef:
              name: facilitator-secrets
              key: evm-private-key
        - name: API_KEYS
          valueFrom:
            secretKeyRef:
              name: facilitator-secrets
              key: api-keys
        - name: ADMIN_API_KEY
          valueFrom:
            secretKeyRef:
              name: facilitator-secrets
              key: admin-api-key
        envFrom:
        - configMapRef:
            name: facilitator-config
        volumeMounts:
        - name: config
          mountPath: /app/config.toml
          subPath: config.toml
          readOnly: true
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 30
          timeoutSeconds: 5
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 10
          timeoutSeconds: 5
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
      volumes:
      - name: config
        configMap:
          name: facilitator-config-file
```

### ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: facilitator-config
data:
  RUST_LOG: "info"
  RPC_URL_BASE: "https://mainnet.base.org"
  RPC_URL_BSC: "https://bsc-dataseed.binance.org"
  SIGNER_TYPE: "private-key"
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: facilitator-config-file
data:
  config.toml: |
    [rate_limiting]
    enabled = true
    requests_per_second = 50

    [cors]
    allowed_origins = ["https://app.example.com"]

    [security]
    log_security_events = true
```

### Secrets

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: facilitator-secrets
type: Opaque
stringData:
  evm-private-key: "0xYourPrivateKeyHere"
  api-keys: "key1,key2,key3"
  admin-api-key: "admin-secret"
```

### Service

```yaml
apiVersion: v1
kind: Service
metadata:
  name: facilitator
spec:
  type: ClusterIP
  selector:
    app: facilitator
  ports:
  - port: 8080
    targetPort: 8080
    protocol: TCP
    name: http
```

### Ingress

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: facilitator
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - facilitator.yourdomain.com
    secretName: facilitator-tls
  rules:
  - host: facilitator.yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: facilitator
            port:
              number: 8080
```

### Deploy

```bash
# Create namespace
kubectl create namespace facilitator

# Apply manifests
kubectl apply -f deployment.yaml -n facilitator
kubectl apply -f service.yaml -n facilitator
kubectl apply -f ingress.yaml -n facilitator

# Check status
kubectl get pods -n facilitator
kubectl logs -f deployment/facilitator -n facilitator
```

## Reverse Proxy

### Nginx

Create `/etc/nginx/sites-available/facilitator`:

```nginx
upstream facilitator {
    server localhost:8080;
    # For multiple instances
    # server localhost:8081;
    # server localhost:8082;
}

server {
    listen 443 ssl http2;
    server_name facilitator.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/facilitator.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/facilitator.yourdomain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;

    location / {
        proxy_pass http://facilitator;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;

        # Keep-alive
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }

    # Rate limiting (optional - facilitator has built-in)
    limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;
    limit_req zone=api_limit burst=20 nodelay;
}

# HTTP to HTTPS redirect
server {
    listen 80;
    server_name facilitator.yourdomain.com;
    return 301 https://$server_name$request_uri;
}
```

Enable and reload:

```bash
sudo ln -s /etc/nginx/sites-available/facilitator /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### Caddy

Create `Caddyfile`:

```caddy
facilitator.yourdomain.com {
    reverse_proxy localhost:8080 {
        # Load balancing for multiple instances
        # lb_policy round_robin
        # to localhost:8080 localhost:8081 localhost:8082
    }

    # Security headers
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Frame-Options "SAMEORIGIN"
        X-Content-Type-Options "nosniff"
    }

    # Automatic HTTPS via Let's Encrypt
    # No additional SSL configuration needed!
}
```

Start:
```bash
caddy run --config Caddyfile
```

## Systemd Service

Create `/etc/systemd/system/facilitator.service`:

```ini
[Unit]
Description=Infra402 Facilitator
After=network.target

[Service]
Type=simple
User=facilitator
Group=facilitator
WorkingDirectory=/opt/facilitator
EnvironmentFile=/opt/facilitator/.env
ExecStart=/opt/facilitator/infra402-facilitator
Restart=always
RestartSec=5

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/facilitator/logs

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=facilitator

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
# Create user
sudo useradd -r -s /bin/false facilitator

# Set permissions
sudo chown -R facilitator:facilitator /opt/facilitator

# Enable service
sudo systemctl daemon-reload
sudo systemctl enable facilitator
sudo systemctl start facilitator

# Check status
sudo systemctl status facilitator

# View logs
sudo journalctl -u facilitator -f
```

## SSL/TLS Certificates

### Let's Encrypt with Certbot

```bash
# Install certbot
sudo apt install certbot python3-certbot-nginx

# Obtain certificate
sudo certbot --nginx -d facilitator.yourdomain.com

# Auto-renewal (already configured by default)
sudo systemctl status certbot.timer
```

### Manual Certificate

```bash
# Generate private key
openssl genrsa -out facilitator.key 2048

# Generate CSR
openssl req -new -key facilitator.key -out facilitator.csr

# Get certificate from CA
# (provide facilitator.csr to your Certificate Authority)

# Install certificate in Nginx/Caddy configuration
```

## Zero-Downtime Deployment

### Rolling Updates (Kubernetes)

```bash
# Update image
kubectl set image deployment/facilitator \
  facilitator=infra402-facilitator:v2 \
  -n facilitator

# Monitor rollout
kubectl rollout status deployment/facilitator -n facilitator

# Rollback if needed
kubectl rollout undo deployment/facilitator -n facilitator
```

### Blue-Green Deployment

```bash
# Deploy new version to port 8081
docker run -d -p 8081:8080 --name facilitator-green \
  --env-file .env infra402-facilitator:v2

# Test green deployment
curl http://localhost:8081/health

# Update nginx upstream to point to 8081
# Reload nginx
sudo systemctl reload nginx

# Stop old version
docker stop facilitator-blue
```

## Monitoring and Alerts

See [Observability Guide](OBSERVABILITY.md) for comprehensive monitoring setup.

### Quick Health Check

```bash
# Check service health
curl https://facilitator.yourdomain.com/health

# Check from monitoring service (cron job)
0 * * * * curl -f https://facilitator.yourdomain.com/health || send_alert
```

## Backup and Disaster Recovery

### Configuration Backup

```bash
# Backup configuration
tar czf facilitator-backup-$(date +%Y%m%d).tar.gz \
  .env config.toml

# Store in S3
aws s3 cp facilitator-backup-*.tar.gz s3://backups/facilitator/
```

### Secret Backup

```bash
# Export secrets (Kubernetes)
kubectl get secret facilitator-secrets -n facilitator -o yaml > secrets-backup.yaml

# Store securely (encrypted)
gpg --encrypt --recipient admin@example.com secrets-backup.yaml
```

### Disaster Recovery Plan

1. **Service Down**: Auto-restart via systemd/Kubernetes
2. **Data Loss**: Restore from configuration backup
3. **Infrastructure Failure**: Redeploy to new infrastructure using backups
4. **Key Compromise**: Rotate keys, update secrets, redeploy

## Scaling

### Horizontal Scaling

**Kubernetes:**
```bash
# Scale to 5 replicas
kubectl scale deployment/facilitator --replicas=5 -n facilitator

# Auto-scaling
kubectl autoscale deployment/facilitator \
  --cpu-percent=70 --min=2 --max=10 -n facilitator
```

**Docker Swarm:**
```bash
docker service scale facilitator=5
```

### Vertical Scaling

**Increase resources (Kubernetes):**
```yaml
resources:
  requests:
    memory: "512Mi"
    cpu: "500m"
  limits:
    memory: "1Gi"
    cpu: "1000m"
```

### Multi-Region Deployment

Deploy facilitator instances in multiple regions with:
- Regional RPC endpoints
- Regional secret storage
- Global load balancer (Cloudflare, AWS Global Accelerator)

## Security Hardening

- ✅ Run as non-root user
- ✅ Use read-only root filesystem where possible
- ✅ Restrict network access (firewall rules)
- ✅ Enable container security scanning
- ✅ Use secret rotation
- ✅ Implement audit logging
- ✅ Regular security updates

## Troubleshooting

See [Observability Guide](OBSERVABILITY.md#debugging) for debugging steps.

### Common Issues

**Service won't start:**
- Check logs: `docker logs facilitator` or `journalctl -u facilitator`
- Verify environment variables
- Check RPC endpoint connectivity

**502 Bad Gateway (Nginx):**
- Verify facilitator is running: `curl localhost:8080/health`
- Check Nginx error logs: `tail -f /var/log/nginx/error.log`

**High memory usage:**
- Increase resources or reduce traffic
- Check for memory leaks in logs
- Monitor with htop/prometheus

## Further Reading

- [Configuration Guide](CONFIGURATION.md) - Configuration options
- [Performance Guide](PERFORMANCE.md) - Scaling and performance tuning
- [Observability Guide](OBSERVABILITY.md) - Monitoring and logging
- [Security Documentation](SECURITY.md) - Security best practices
