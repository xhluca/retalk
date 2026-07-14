# Running the server on a Google Cloud VM

This walks through putting `retalk-server` on a small Google Cloud VM: a
free-tier-sized machine, locked-down SSH, installing retalk, and the
commands to stop and delete it when you're done. Everything here was run
end to end on a fresh project.

For the public-HTTPS half there are two options, covered at the end of
this page: serve your own domain straight from the VM with Caddy (opens
ports 80/443), or hold a Cloudflare Tunnel open (outbound-only — no
inbound ports at all; see [cloudflare.md](cloudflare.md)). Everything else
on this page is just the machine.

## Before you start

Install the gcloud CLI (https://cloud.google.com/sdk/docs/install) and log
in:

```sh
gcloud auth login
```

## One-time project setup

Create a project and attach a billing account (find your billing ID with
`gcloud billing accounts list`):

```sh
gcloud projects create my-retalk --name="my-retalk"
gcloud billing projects link my-retalk --billing-account=XXXXXX-XXXXXX-XXXXXX
gcloud config set project my-retalk
gcloud services enable compute.googleapis.com iap.googleapis.com
```

Enabling the APIs takes about a minute. `iap.googleapis.com` is for
keyless SSH over Identity-Aware Proxy, so you never expose port 22 to the
internet.

If `billing projects link` fails with "Cloud billing quota exceeded," the
billing account has hit its limit on linked projects. Unlink an unused
project (Cloud Console -> Billing -> Account management) or request a quota
increase, then retry.

## Lock down SSH

A new project's default network opens SSH (and RDP) to the **entire
internet** (`0.0.0.0/0`). Delete those default rules, then allow SSH only
from Google's IAP range so you reach the VM over Identity-Aware Proxy:

```sh
# remove the internet-facing defaults (RDP isn't used on Linux anyway)
gcloud compute firewall-rules delete default-allow-ssh default-allow-rdp --quiet

# allow SSH only from Google's IAP range
gcloud compute firewall-rules create allow-iap-ssh \
  --direction=INGRESS --action=ALLOW \
  --rules=tcp:22 --source-ranges=35.235.240.0/20
```

After this the VM has no inbound ports open to the public internet. Adding
the IAP rule without deleting `default-allow-ssh` would leave SSH exposed,
so don't skip the delete.

## Create the VM

`e2-micro` in `us-central1` is the smallest general-purpose machine and is
free-tier eligible (one per month in `us-west1`, `us-central1`, or
`us-east1`). Debian 12, a 10 GB standard disk:

```sh
gcloud compute instances create retalk-server \
  --zone=us-central1-a \
  --machine-type=e2-micro \
  --image-family=debian-12 --image-project=debian-cloud \
  --boot-disk-size=10GB --boot-disk-type=pd-standard \
  --no-service-account --no-scopes
```

This gives the VM an ephemeral external IP, which it needs for outbound
internet (installing packages, and the outbound Cloudflare Tunnel). Don't
use `--no-address` here: a VM with no external IP has no internet access at
all unless you also set up Cloud NAT, which costs far more than the IP does
for a single machine.

`--no-service-account --no-scopes` is a deliberate security choice, not a
default; see [Security](#security) below for why it matters.

## Connect and install retalk

SSH in over IAP (the first connection generates a key and can take a
minute):

```sh
gcloud compute ssh retalk-server --zone us-central1-a --tunnel-through-iap
```

On the VM, install retalk into a virtualenv:

```sh
sudo apt-get update && sudo apt-get install -y python3-venv
python3 -m venv ~/rt
~/rt/bin/pip install retalk
```

Quick check that it works, using a local loopback server:

```sh
RETALK_SERVER_DB=/tmp/s.db RETALK_SERVER_HOST=127.0.0.1 RETALK_SERVER_PORT=8766 \
  RETALK_SERVER_AUDIENCE=http://127.0.0.1:8766 ~/rt/bin/retalk-server &
export RETALK_RELAY=http://127.0.0.1:8766
RETALK_PASSPHRASE=a ~/rt/bin/retalk init --dir ~/alice --display-name alice
# ... add a peer, send, receive — see the main README
```

To make the server reachable from other machines, give it a public HTTPS
URL and set `RETALK_SERVER_AUDIENCE` to that URL. Two ways:

- **Your own domain, served from the VM (Caddy).** An A record points at
  the VM's IP and [Caddy](https://caddyserver.com) terminates TLS with an
  automatic Let's Encrypt certificate. Opens ports 80/443 and makes the
  VM's IP public; steps below.
- **Cloudflare Tunnel.** No inbound ports at all; the VM dials out to
  Cloudflare. Follow [cloudflare.md](cloudflare.md) on this same VM;
  nothing GCP-specific changes. The tunnel's DNS route must live in the
  same Cloudflare account that owns the tunnel.

For the Caddy way, first pin the VM's IP (so it survives a stop/start) and
open HTTP/HTTPS for this VM only:

```sh
IP=$(gcloud compute instances describe retalk-server --zone us-central1-a \
  --format="value(networkInterfaces[0].accessConfigs[0].natIP)")
gcloud compute addresses create retalk-relay-ip --region=us-central1 --addresses="$IP"
gcloud compute firewall-rules create retalk-relay-https --allow=tcp:80,tcp:443 \
  --source-ranges=0.0.0.0/0 --target-tags=retalk-relay
gcloud compute instances add-tags retalk-server --zone=us-central1-a --tags=retalk-relay
```

Create an A record for your hostname (say `relay.example.com`) pointing at
that IP. If the zone lives on Cloudflare, set the record to **DNS only**,
so Caddy can answer the ACME challenge itself. Then, on the VM:

```sh
sudo apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf "https://dl.cloudsmith.io/public/caddy/stable/gpg.key" | sudo gpg --yes --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf "https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt" | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt-get update && sudo apt-get install -y caddy
printf "%s\n" "relay.example.com {" "    reverse_proxy 127.0.0.1:8766" "}" | sudo tee /etc/caddy/Caddyfile
sudo systemctl enable --now caddy
sudo systemctl reload caddy
```

Caddy fetches the certificate on the first request and renews it by
itself. The retalk server keeps listening on `127.0.0.1:8766`, now with
`RETALK_SERVER_AUDIENCE=https://relay.example.com`.

## Security

This server faces the internet, so assume the box can be probed and harden
for the case where it is compromised.

**Give the VM no cloud identity.** Every Compute Engine VM can read an
OAuth token for its attached service account from the metadata server
(`169.254.169.254`). By default that is the project's Compute service
account, which often holds the broad `roles/editor` role — so anything that
runs code on the VM could use that token to act on your whole GCP project
(read storage, create resources, run up a bill). retalk needs no Google
APIs at all, so the create command above uses `--no-service-account
--no-scopes`. With no identity attached, a stolen metadata token is
useless. (Project-wide, it is also worth removing `roles/editor` from the
default Compute service account; Google
[recommends this](https://cloud.google.com/iam/docs/best-practices-service-accounts#default-service-account).)

**Keep SSH off the public internet.** The firewall rule above only allows
SSH from Google's IAP range. On the tunnel setup the VM has no other
inbound ports open at all (the Cloudflare Tunnel is outbound-only); on the
Caddy setup only 80/443 are open, and only Caddy listens there. Either
way, do not add a `0.0.0.0/0` rule for port 22 or for retalk's port.

**What a full compromise would expose.** Even if someone got root on the
VM and copied the database, retalk stores only public key material and
ciphertext (deleted on delivery). They could not read message content,
recover anyone's private keys, or impersonate users (clients verify key
fingerprints). They could see metadata - which user IDs talk to which, and
when - and disrupt service. That is the design's accepted trade-off; the
hardening above keeps a server compromise from spreading to your GCP or
Cloudflare accounts.

**Keep the OS patched** (`sudo apt-get update && sudo apt-get upgrade`).

## Cost

All prices below are us-central1, on-demand, running 24/7 (730 hours per
month). Sources:
[VM instance pricing](https://cloud.google.com/compute/vm-instance-pricing),
[disk pricing](https://cloud.google.com/compute/disks-image-pricing),
[external IP pricing](https://cloud.google.com/vpc/network-pricing#ipaddress),
[Always Free tier](https://cloud.google.com/free/docs/free-cloud-features#compute),
[Spot VMs](https://cloud.google.com/spot-vms).

The monthly floor for this setup is one e2-micro, its external IP, and a
10 GB disk:

| Item | Rate | Per month (rate x 730 h) |
|---|---|---|
| e2-micro compute | $0.00837/hour | $6.11 |
| External IPv4 (in use) | $0.005/hour | $3.65 |
| 10 GB standard disk | $0.040/GB-month | $0.40 |
| **Floor total** | | **$10.16/month** |

How that floor changes:

- **Free tier**: one e2-micro per month is free in us-west1, us-central1,
  or us-east1, and the first 30 GB of standard disk is free. That zeroes
  the compute and disk lines, leaving only the IP: **~$3.65/month**.
- **Stopped**: a stopped VM bills no compute and releases its ephemeral
  IP, so you pay only for the disk: **~$0.40/month** (10 GB x $0.040).
- **Deleted**: $0.

A short test (create, try it, delete within the hour) costs a few cents.

This guide uses standard on-demand VMs for reliability. Spot VMs are about
half the price, but Google can preempt (shut down) them at any time, so
they are not suitable for a relay that needs to stay up.

## Scaling up

retalk is light. The server is a small Python process backed by SQLite: it
stores public keys and one-time keys, holds messages only until they are
delivered, then deletes them. For most setups the machine is not the
limit, and an e2-micro comfortably handles dozens of users.

What actually grows with usage:

- **Request rate.** Each client polls (default every 2 seconds) and sends.
  That is roughly N/2 requests per second for N users. Each request is one
  signature check plus a small SQLite query.
- **Storage.** A few KB per user for their published one-time keys, plus
  any undelivered messages (deleted once received). Even hundreds of users
  stay in the low megabytes, well under a 10 GB disk.
- **Egress.** Ciphertext is small, so bandwidth cost is negligible at
  these sizes.

For **10-100 users you do not need to scale at all** - an e2-micro is
plenty, so the cost stays at the floor above (~$10/month on-demand, or
~$3.65/month if the compute is free-tier eligible). Move up only if you
see sustained CPU saturation or memory pressure (check `top` over SSH).

A rough on-demand ladder (us-central1, 24/7; each total adds the $3.65 IP
and $0.40 disk to the compute price):

| Users (rough) | Machine | vCPU / RAM | Compute/mo | Total/mo |
|---|---|---|---|---|
| 1-100 | e2-micro | shared / 1 GB | $6.11 | ~$10 |
| 100-1,000 | e2-small | shared / 2 GB | $12.23 | ~$16 |
| ~1,000+ | e2-medium | shared / 4 GB | $24.46 | ~$29 |
| heavy | e2-standard-2 | 2 / 8 GB | $48.92 | ~$53 |

These are generous upper bounds; retalk is unlikely to need more than an
e2-micro for 10-100 users.

The real ceiling is the software, not the VM. The built-in HTTP server and
single-writer SQLite are simple by design. Long before a bigger machine
helps, very high traffic would be better handled by running the server
behind a production HTTP host and a database that allows concurrent
writes - that is a code change, not a larger VM. For 10-100 users you are
nowhere near this.

Resizing an existing VM (it must be stopped first):

```sh
gcloud compute instances stop retalk-server --zone us-central1-a
gcloud compute instances set-machine-type retalk-server \
  --zone us-central1-a --machine-type=e2-small
gcloud compute instances start retalk-server --zone us-central1-a
```

Machine types and their prices are listed under
[VM instance pricing](https://cloud.google.com/compute/vm-instance-pricing).

## Stop and delete

Stop the VM when you're not using it. A stopped VM costs nothing for
compute, and its ephemeral IP is released, so you only pay for the 10 GB
disk (about $0.40/month):

```sh
gcloud compute instances stop retalk-server --zone us-central1-a
gcloud compute instances start retalk-server --zone us-central1-a   # later
```

Delete it for good (this destroys the disk and everything on it):

```sh
gcloud compute instances delete retalk-server --zone us-central1-a
gcloud compute firewall-rules delete allow-iap-ssh
```

Or remove the whole project, which deletes every resource and stops all
billing for it:

```sh
gcloud projects delete my-retalk
```
