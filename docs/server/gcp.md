# Running the server on a Google Cloud VM

This walks through putting `retalk-server` on a small Google Cloud VM: a
free-tier-sized machine, locked-down SSH, installing retalk, and the
commands to stop and delete it when you're done. Everything here was run
end to end on a fresh project.

The VM only needs to make outbound connections (to install software and,
once running, to hold a Cloudflare Tunnel open). It does not need any
inbound ports open to the world. See [cloudflare.md](cloudflare.md) for
the public-HTTPS half; this page is just the machine.

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

Allow SSH only from Google's IAP range, not from the whole internet:

```sh
gcloud compute firewall-rules create allow-iap-ssh \
  --direction=INGRESS --action=ALLOW \
  --rules=tcp:22 --source-ranges=35.235.240.0/20
```

## Create the VM

`e2-micro` in `us-central1` is the smallest general-purpose machine and is
free-tier eligible (one per month in `us-west1`, `us-central1`, or
`us-east1`). Debian 12, a 10 GB standard disk:

```sh
gcloud compute instances create retalk-server \
  --zone=us-central1-a \
  --machine-type=e2-micro \
  --image-family=debian-12 --image-project=debian-cloud \
  --boot-disk-size=10GB --boot-disk-type=pd-standard
```

This gives the VM an ephemeral external IP, which it needs for outbound
internet (installing packages, and the outbound Cloudflare Tunnel). Don't
use `--no-address` here: a VM with no external IP has no internet access at
all unless you also set up Cloud NAT, which costs far more than the IP does
for a single machine.

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
SERVER_DB=/tmp/s.db SERVER_HOST=127.0.0.1 SERVER_PORT=8766 \
  SERVER_AUDIENCE=http://127.0.0.1:8766 ~/rt/bin/retalk-server &
export SERVER_URL=http://127.0.0.1:8766
PICKLE_SECRET=a ~/rt/bin/retalk init ~/alice --name alice
# ... add a peer, send, receive — see the main README
```

To make the server reachable from other machines, run it behind a
Cloudflare Tunnel and set `SERVER_AUDIENCE` to the public URL. Follow
[cloudflare.md](cloudflare.md) on this same VM; nothing GCP-specific
changes.

## Cost

In a free-tier region, running 24/7:

- `e2-micro` compute: free (one per month), otherwise about $6-7/month.
- 10 GB standard disk: free (under the 30 GB free tier), otherwise about
  $0.40/month.
- Ephemeral external IP: about $0.005/hour, roughly $3.65/month while the
  VM is running. This is the one charge you can't avoid for a single
  internet-connected VM.

So expect roughly $4/month within the free tier, mostly the IP address. A
short test costs cents.

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
