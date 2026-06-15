# Putting the server on the internet with Cloudflare Tunnel

`retalk-server` listens on plain HTTP on a local port. To reach it from
other machines you need a public HTTPS address. Cloudflare Tunnel gives you
one without opening a firewall port or running your own TLS certificate:
`cloudflared` makes an outbound connection to Cloudflare, and Cloudflare
forwards public requests back down that connection to your local server.

There are two ways to do it:

- **Quick tunnel** (`trycloudflare.com`): free, no account, no domain. You
  get a random `https://<words>.trycloudflare.com` URL that lasts until you
  stop `cloudflared`. Good for a quick test or a throwaway server.
- **Named tunnel**: uses your own domain on your Cloudflare account, with a
  stable hostname that survives restarts. Use this for anything real.

## The one rule that matters for retalk

The server signs nothing, but clients sign every request and bind the
signature to the server URL. So **`SERVER_AUDIENCE` must be the exact public
URL clients use** — the `https://...` Cloudflare address, not
`http://localhost:8766`. If they disagree, every request fails signature
verification. Cloudflare terminates TLS at its edge and forwards plain HTTP
to your local server, so the server itself still speaks HTTP; only the
public URL is HTTPS.

## Quick tunnel (free, no account)

Install `cloudflared` first (https://github.com/cloudflare/cloudflared).

1. Start the tunnel pointing at the port the server will use, and copy the
   URL it prints:

   ```sh
   cloudflared tunnel --url http://localhost:8766
   # ...
   # |  https://race-content-september-gary.trycloudflare.com   |
   ```

2. In another terminal, start the server with that URL as its audience:

   ```sh
   SERVER_PORT=8766 \
   SERVER_AUDIENCE=https://race-content-september-gary.trycloudflare.com \
     retalk-server
   ```

3. Point clients at the same URL:

   ```sh
   retalk init -u --name alice \
     --server https://race-content-september-gary.trycloudflare.com
   retalk send bob "hello through cloudflare"
   ```

The URL changes every time you restart the quick tunnel, so it's only
useful while that `cloudflared` process keeps running.

## Named tunnel (your own domain, stable)

This needs a Cloudflare account with your domain added as a zone (its
nameservers pointing at Cloudflare). Replace `retalk.example.com` with a
hostname on your domain.

**For a server, prefer a scoped token (more secure).** The `cloudflared
tunnel login` flow below writes `~/.cloudflared/cert.pem`, which can create
tunnels and change DNS across your *whole* Cloudflare zone. If that VM is
compromised, so is your zone. A per-tunnel token avoids this:

1. In the Cloudflare Zero Trust dashboard, go to **Networks -> Tunnels ->
   Create a tunnel**, name it, and copy the token it shows.
2. On the VM, run the tunnel with only that token (no login, no `cert.pem`):

   ```sh
   cloudflared tunnel run --token <TOKEN>
   ```

3. On the same dashboard page, add a **public hostname**
   (`retalk.example.com`) routing to `http://localhost:8766`.

The token controls only that one tunnel, so a compromised VM can't reach
the rest of your Cloudflare account. The file-based steps below are the
alternative if you prefer to manage the tunnel from the machine.

1. Log in once. This opens a browser; pick the zone for your domain. It
   writes `~/.cloudflared/cert.pem`, scoped to that zone:

   ```sh
   cloudflared tunnel login
   ```

2. Create the tunnel. This writes a credentials file
   `~/.cloudflared/<UUID>.json` and prints the tunnel's UUID:

   ```sh
   cloudflared tunnel create retalk
   ```

3. Point a hostname at the tunnel (creates a proxied CNAME in your zone):

   ```sh
   cloudflared tunnel route dns retalk retalk.example.com
   ```

   The hostname must be one level under the zone you logged into. If you
   logged into `example.com`, `retalk.example.com` works; a deeper name
   like `retalk.sub.example.com` won't be covered by Cloudflare's default
   certificate and HTTPS will fail.

4. Write a config file, e.g. `~/.cloudflared/retalk.yml` (use the UUID and
   credentials path from step 2):

   ```yaml
   tunnel: <UUID>
   credentials-file: /home/you/.cloudflared/<UUID>.json
   ingress:
     - hostname: retalk.example.com
       service: http://localhost:8766
     - service: http_status:404
   ```

5. Run the tunnel, and start the server with the public hostname as its
   audience:

   ```sh
   cloudflared tunnel --config ~/.cloudflared/retalk.yml run retalk
   # in another terminal:
   SERVER_PORT=8766 SERVER_AUDIENCE=https://retalk.example.com retalk-server
   ```

   Clients then use `--server https://retalk.example.com`.

To run both as background services on a server, install `cloudflared` as a
service (`cloudflared service install`) and run `retalk-server` under your
init system (systemd, etc.); see the deployment notes in the main README.

## Tearing a named tunnel down

```sh
cloudflared tunnel delete retalk          # removes the tunnel
```

Deleting the tunnel does not remove the CNAME it created. Remove
`retalk.example.com` from your Cloudflare DNS dashboard (or via the
Cloudflare API) when you're done.
