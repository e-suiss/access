# Small provider

One host runs a whole Access provider: `access-server`, the authority signer and the identity
signer as three processes, one PostgreSQL 18 and one PKCS#11 token (SoftHSM or an HSM). The
signers stay separate processes reached only over their Unix sockets, as in every other form.

```sh
sudo deploy/small-provider/install.sh /etc/access/access.toml
```

Before you run it:

1. Put `access-server`, `access-signer` and `access-identity-signer` in `/usr/local/bin`.
2. Create the database and its roles (`crates/store/bootstrap/roles.sql` and `database.sql`).
3. Copy `access.toml`, `access-signer.toml` and `access-identity-signer.toml` to `/etc/access`,
   replace every `example.org` name, and put each password, PIN and key file where the
   configuration names it. Secrets are files; none is read from the environment.
4. Optionally add `/etc/access/bootstrap.toml` with the tenants to create.

The script provisions the signers' keys, migrates the schema, installs and starts the three
systemd units, and bootstraps the tenants.

## What the profile declares

`durability = "single-node"`. Every domain this provider leads publishes `durability:
single-node` and its residency in its Domain Metadata, and `GET
/admin/v1/realms/{slug}/durability` says the same. An acknowledged write can be lost if the node
or its disk is lost. Revocations and the other writes that need an acknowledgement still wait for
a declared replica and an independent witness; without them they stay pending, never confirmed.

PostgreSQL is the only database: a SQLite host or file name refuses the start.
