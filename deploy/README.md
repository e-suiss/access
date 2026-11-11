# Deploying Access

Access ships as one set of binaries in one mode. Development and production differ only in
configuration; there is no build flag and no "dev" code path. The signers (`access-signer`,
`access-identity-signer`) are always separate processes next to `access-server`, in every form
below, the smallest included.

## Deployment forms

| Form | What runs | Who operates it |
|---|---|---|
| Suiss-hosted, shared cell | Many tenants, realms and domains in one cell | Suiss |
| Suiss-hosted, dedicated cell | One large tenant or organization in a cell of its own | Suiss |
| Self-hosted | Your own provider from these binaries: the single-node small-provider profile or a full cell | You |
| Third-party provider | Another implementation built on the open Kernel and spec, checked by the conformance suite and test vectors | That provider |

The form never changes the protocol. A domain's records, receipts and exports verify the same way
under every form.

**Suiss-hosted operation.** Suiss runs the cells, their databases, HSMs, upgrades, backups and
drills. Customers see the console, the APIs and the published Domain Metadata of their domains.

**Leaving Suiss-hosted.** A self-hosted provider can take a domain over at any time: the domain's
root exports its records (`access-verify export` checks the package without Suiss), the new
provider replays them and the domain is handed over. Nothing about leaving needs Suiss's
cooperation beyond serving the export the root asks for.

### Small provider (single node)

`deploy/small-provider/` is the smallest self-hosted install: one `access-server`, the two signer
processes, one PostgreSQL and a PKCS#11 token (SoftHSM or an HSM), installed by one command:

```sh
sudo deploy/small-provider/install.sh /etc/access/access.toml
```

It declares `durability = "single-node"`. Every domain it leads publishes `durability:
single-node` in its Domain Metadata and every realm's durability read says so. An acknowledged
write can be lost with the node, and the profile says so instead of hiding it. Revocations and
other SEC23 writes still wait for a declared replica and an independent witness before they are
acknowledged; without them they stay pending.

PostgreSQL is the only database. Access refuses to start with a SQLite URL or file name: a
SQLite-backed identity plane is a choice a third-party provider may make, not one these binaries
offer.

## Cells

A cell is a region's unit of residency: its own Kubernetes cluster across at least three zones,
its own canonical PostgreSQL (a primary and at least two synchronous standbys, `ANY 1`), the
derived index, optional NATS and its HSM. No data is replicated between cells.

```toml
[cells]
this = "eu-central-1"

[[cells.cell]]
name = "eu-central-1"
region = "eu-central"
class = "regional"            # or multi-region-sync
url = "https://eu1.access.example"

[[cells.cell]]
name = "acme-dedicated"
region = "eu-central"
url = "https://acme.access.example"
dedicated_to = "0190f1c2-7d3e-7a10-8000-5d1e4a6b2c01"
```

Each cell records its profile (name, region, class, durability, dedicated tenant) at start. A
dedicated cell holds its one tenant and refuses every other.

### Placement Directory

The directory maps a tenant, a realm and a domain to the cell that serves it, one version per
move, never edited. It is routing only:

- A request for a domain placed in another cell is answered `421 placement-mismatch` with the
  cell's name in `access-cell` and its URL in `location`.
- A subject with no placement is served by the cell that holds it.
- When the directory cannot answer, the request goes on; the commit path decides. A cell that
  does not lead the domain, or holds it sealed, refuses it there.

### Moving between cells

A domain moves by a seal and an acceptance: the source cell seals its head, the target replays the
whole image, checks the chain, the Merkle root and the fold from Genesis, and accepts the domain
at the next epoch. Only then does the placement change. A silo move does this for every domain of
a tenant, adopts the tenant in the target cell with its own id and places it there; a dedicated
cell is the usual target. The tenant's identity-plane rows move by a side restore and a logical
transfer, never by row-level restore into a live cell.

### Residency

A domain's residency is the region of the cell that leads it, published in its Domain Metadata
with the cell's class (`regional` or `multi-region-sync`). A realm declares its residency with
`PUT /admin/v1/realms/{slug}/settings/residency` (`idp.realm.residency`, CT3); a realm can only
declare the region its cell is in, so changing it means moving the realm's domain first. A
regional cell's RPO is 0 inside the region; an async DR profile (`settings/dr-profile`) declares
its own RPO. `GET /admin/v1/realms/{slug}/durability` reads all of it back, with the witnesses and
replicas the governing domain declares.

### Rehoming a realm

`POST /admin/v1/realms/{slug}/rehome` with `{"domain": "<new domain>", "target_ais": "<AIS>"}`
moves a realm to another governing domain. It is two-ended: one Exercise of `idp.realm.rehome` is
committed in the current governing domain (the request's AIS) and one in the new domain (the
`target_ais`, signed for the new domain on an Anchor of its own that covers the realm). The realm
moves only in the transaction that records the second end; with one end the answer is `409
rehome-incomplete` and the realm stays.

### A local AuthorityDomain

A plant, a robot fleet or an air-gapped site can run its own domain on its own small provider or
cell, and still take part in the main domain's decisions:

1. The site's provider creates the local domain with its own Genesis and root.
2. The local domain accepts the main domain's binding key and the Claim classes it will rely on.
3. The local root issues a bridging Grant whose holder is the main domain's authority of one
   class, with the ceiling it allows.

The local domain decides on its own while it is cut off; the main domain's PAPs count there only
through that Grant and only up to its ceiling. This is a deployment pattern, not a profile class.

## Topology phases

| Phase | Topology | In Access |
|---|---|---|
| Small (about 100 users) | One node, one PostgreSQL, daily dump and WAL archive | Small-provider profile, `durability: single-node` |
| Phase 1 (about 100 000 users) | One region, three zones, three stateless nodes, PostgreSQL primary and two synchronous standbys | One cell |
| Phase 2 | Two independent clusters in one region over one synchronously replicated database, the sites close enough for synchronous commits | Two Kubernetes clusters in a cell; still one linearizable store |
| Phase 3 | One cell per region, no data replicated between cells, a small global control plane (tenant to cell) | Cells and the Placement Directory |
| Large (about 10 million users) | A separate node pool for Argon2, load shedding, larger caches, read replicas for allowed queries only | Identity plane scale; authority domains spread over cells |

Red lines in every phase: no Redis pub/sub for revocation, no revocation or session reads from a
replica, no logical-replication active-active or last-writer-wins, no multi-primary without a
quorum, no synchronous writes across continents, no `synchronous_commit = on` with one standby, no
promote across cells without a fence proof.

## Kubernetes

`helm/access` is the first-class chart; `k8s/` is the same cell as kustomize. Both carry:

- preStop 5 s, then the server's own 2 s drain (not ready, still serving) and 15 s shutdown bound,
  inside a 45 s grace period;
- a PodDisruptionBudget of one, a hard spread across at least three zones and a soft one across
  hosts;
- startup, liveness and readiness on the internal port. Liveness never waits on readiness, and
  schema migrations run as their own Job, so a long migration never restarts the server;
- readiness only after every realm's issuer and JWKS loaded (the server does not start
  otherwise) and a random start jitter of up to 5 s.

`values-small-provider.yaml` is the single-node profile on Kubernetes and
`values-plane-split.yaml` gives the authority plane's and the identity plane's signers separate
secret stores and operator roles. `just helm-check` compares the chart with its committed renders
in `helm/access/rendered/`.

An operator is optional and is not part of the chart.

## OpenTofu

`tofu/` provisions infrastructure only: the namespace, the database cluster's place, the secret
store roles and the chart release. Realm and domain configuration is never infrastructure: it is
an Exercise through the management API, so no `.tf` file in `tofu/` calls an `idp.*` action or the
decision API. `cargo xtask check` enforces this.

## Hosted cells

The hosted stack of a Suiss cell is Kubernetes per cell, OpenTofu, Argo CD, Cilium with Envoy
Gateway and SPIFFE/SPIRE for service identity. The admission policy that admits only signed
images is in `k8s/admission/`.
