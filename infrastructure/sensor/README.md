# Sensor deployment

Turns a fresh **Ubuntu 24.04** VM into the internet-facing honeypot. Provider-neutral;
the steps below use **Azure for Students** (no credit card).

What `setup-sensor.sh` does:

- installs Cowrie (pinned tag) as a sandboxed systemd service
- moves the real sshd to a private admin port (key-only)
- sends port 22 to Cowrie
- blocks all new outbound traffic
- restricts the log-pull key to read-only access of the log folder

A 15-minute rollback timer undoes the network changes unless you confirm, so a
mistake can't lock you out.

| File | Purpose |
|---|---|
| `setup-sensor.sh` | One-shot provisioning (safe to re-run) |
| `render-nftables.sh` | Generates the firewall ruleset |
| `cowrie.service` | systemd unit with sandboxing |
| `egress-window` | Opens outbound traffic for updates, with Cowrie stopped |
| `sensor-rollback` / `sensor-confirm` | Lockout protection |
| `sensor.env.example` | Settings template. The real `sensor.env` is **never committed** |
| `test/firewall-test.sh` | Proves the firewall policy in two local containers |

## Before you start (on your PC)

```powershell
ssh-keygen -t ed25519 -f $HOME\.ssh\sensor_admin     # to log in as admin
ssh-keygen -t ed25519 -f $HOME\.ssh\sensor_logpull   # only for pulling logs
```

Pick a random admin port between 40000 and 60000 and write it down.

## 1. Create the VM (Azure portal)

1. **Create a resource → Virtual machine**
   - Image: **Ubuntu Server 24.04 LTS**
   - Size: **B1s** (covered by the student free hours)
   - Authentication: **SSH public key**; paste `sensor_admin.pub`; username `azureuser`
   - Inbound ports: **SSH (22)**, restricted to your IP in the next step
2. After it's created, open the VM's **Networking** settings and edit the inbound rules:
   - SSH 22: source **My IP address** only (not the whole internet yet)
   - Add a rule: your admin port, TCP, source **My IP address**
3. Note the public IP. Don't share it or put it in screenshots.

## 2. Run the setup

```powershell
scp -i $HOME\.ssh\sensor_admin -r infrastructure\sensor azureuser@<IP>:~/sensor
ssh -i $HOME\.ssh\sensor_admin azureuser@<IP>
```

On the VM:

```bash
cd ~/sensor
cp sensor.env.example sensor.env
nano sensor.env          # ADMIN_PORT, PULL_PUBKEY (contents of sensor_logpull.pub), COWRIE_HOSTNAME
sudo bash setup-sensor.sh
```

## 3. Confirm within 15 minutes

Keep the first window open. In a **new** PowerShell window:

```powershell
ssh -i $HOME\.ssh\sensor_admin -p <ADMIN_PORT> azureuser@<IP>
sudo sensor-confirm
```

Check that the honeypot answers on 22. You'll land in Cowrie's fake shell, not the real machine:

```powershell
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL root@<IP>
```

## 4. Go live

In Azure, change the **SSH 22** inbound rule's source from *My IP* to **Any**.
Bots usually find it within minutes to hours.

## Maintenance

```bash
sudo egress-window open 20      # stops Cowrie, allows apt/pip for 20 min
sudo apt-get update && sudo apt-get upgrade -y
sudo egress-window close        # restores the lockdown, restarts Cowrie
```

Kill switch (full steps in [docs/threat-model.md](../../docs/threat-model.md#kill-switch)):
set the cloud inbound rule for 22 to **Deny**, pull the logs, then `sudo systemctl stop cowrie`.
