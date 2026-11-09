//! The identity plane's agent records (OP-154 m.3 (c), (e), (g), AG-20, AG-41): the agent row
//! bound to its own agent Party, human sponsorship episodes and versioned Grant templates. They
//! hold no authority (AG-19); nothing is deleted (OP-73).

use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::TenantTx;

fn id16(v: Vec<u8>) -> Result<[u8; 16], StoreError> {
    <[u8; 16]>::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn id32(v: Vec<u8>) -> Result<[u8; 32], StoreError> {
    <[u8; 32]>::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn ms(t: i64) -> u64 {
    u64::try_from(t).unwrap_or(0)
}

/// An agent of the realm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentRow {
    /// Its own agent Party in the realm's governing domain.
    pub party: [u8; 16],
    /// The operator Party: an organization or a person.
    pub operator: [u8; 16],
    /// `cloud`, `local`, `enterprise` or `robot`.
    pub kind: String,
    /// Name shown to people.
    pub display_name: String,
    /// Description shown to people.
    pub description: Option<String>,
    /// `active`, `suspended` or `retired`.
    pub status: String,
    /// The `idp.agent.register` Exercise.
    pub registered: [u8; 32],
    /// Unix milliseconds.
    pub created_ms: u64,
    /// When the status last changed, Unix milliseconds.
    pub status_ms: u64,
}

/// A new agent.
#[derive(Clone, Copy, Debug)]
pub struct NewAgent<'a> {
    /// Its agent Party.
    pub party: [u8; 16],
    /// The operator Party.
    pub operator: [u8; 16],
    /// Its kind.
    pub kind: &'a str,
    /// Name shown to people.
    pub display_name: &'a str,
    /// Description shown to people.
    pub description: Option<&'a str>,
    /// The `idp.agent.register` Exercise.
    pub exercise: &'a [u8; 32],
}

/// One sponsorship episode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SponsorRow {
    /// The sponsor's subject.
    pub subject: [u8; 16],
    /// The Exercise that assigned it.
    pub assigned: [u8; 32],
    /// Unix milliseconds.
    pub assigned_ms: u64,
    /// When it ended, Unix milliseconds.
    pub ended_ms: Option<u64>,
    /// `remove`, `account` or `retire`.
    pub ended_by: Option<String>,
    /// The Exercise that ended it, when one did.
    pub ended: Option<[u8; 32]>,
}

/// One template version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemplateRow {
    /// Its name.
    pub name: String,
    /// Its version.
    pub version: u64,
    /// Its dCBOR content.
    pub content: Vec<u8>,
    /// The `idp.agent.template_define` Exercise.
    pub defined: [u8; 32],
}

impl TenantTx {
    /// Records an agent bound to its registered agent Party (OP-154 m.3 (c)).
    ///
    /// # Errors
    /// [`StoreError`]; a Party already bound is an integrity error.
    pub async fn insert_agent(&mut self, a: &NewAgent<'_>) -> Result<(), StoreError> {
        let (tenant, realm) = self.org_scope()?;
        sqlx::query!(
            r#"INSERT INTO access.agents
                 (tenant_id, realm_id, party, operator, agent_kind, display_name, description,
                  registered_exercise)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"#,
            tenant,
            realm,
            a.party.as_slice(),
            a.operator.as_slice(),
            a.kind,
            a.display_name,
            a.description,
            a.exercise.as_slice(),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// The agent bound to `party`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn agent(&mut self, party: [u8; 16]) -> Result<Option<AgentRow>, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let row = sqlx::query!(
            r#"SELECT party, operator, agent_kind, display_name, description, status,
                      registered_exercise,
                      (extract(epoch FROM created_at) * 1000)::bigint AS "created_ms!",
                      (extract(epoch FROM status_at) * 1000)::bigint AS "status_ms!"
               FROM access.agents
               WHERE tenant_id = $1 AND realm_id = $2 AND party = $3"#,
            tenant,
            realm,
            party.as_slice(),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        row.map(|r| {
            Ok(AgentRow {
                party: id16(r.party)?,
                operator: id16(r.operator)?,
                kind: r.agent_kind,
                display_name: r.display_name,
                description: r.description,
                status: r.status,
                registered: id32(r.registered_exercise)?,
                created_ms: ms(r.created_ms),
                status_ms: ms(r.status_ms),
            })
        })
        .transpose()
    }

    /// A page of the realm's agents by Party, after `after`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn agents(
        &mut self,
        after: Option<[u8; 16]>,
        limit: u32,
    ) -> Result<Vec<AgentRow>, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let after = after.map_or_else(Vec::new, |a| a.to_vec());
        let rows = sqlx::query!(
            r#"SELECT party, operator, agent_kind, display_name, description, status,
                      registered_exercise,
                      (extract(epoch FROM created_at) * 1000)::bigint AS "created_ms!",
                      (extract(epoch FROM status_at) * 1000)::bigint AS "status_ms!"
               FROM access.agents
               WHERE tenant_id = $1 AND realm_id = $2 AND party > $3
               ORDER BY party LIMIT $4"#,
            tenant,
            realm,
            after.as_slice(),
            i64::from(limit),
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(AgentRow {
                    party: id16(r.party)?,
                    operator: id16(r.operator)?,
                    kind: r.agent_kind,
                    display_name: r.display_name,
                    description: r.description,
                    status: r.status,
                    registered: id32(r.registered_exercise)?,
                    created_ms: ms(r.created_ms),
                    status_ms: ms(r.status_ms),
                })
            })
            .collect()
    }

    /// Changes an agent's name and description.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn update_agent(
        &mut self,
        party: [u8; 16],
        display_name: &str,
        description: Option<&str>,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let done = sqlx::query!(
            r#"UPDATE access.agents SET display_name = $4, description = $5
               WHERE tenant_id = $1 AND realm_id = $2 AND party = $3 AND status <> 'retired'"#,
            tenant,
            realm,
            party.as_slice(),
            display_name,
            description,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Moves an agent to `status` (`active`, `suspended` or `retired`); a retired agent stays
    /// retired.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn set_agent_status(
        &mut self,
        party: [u8; 16],
        status: &str,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let done = sqlx::query!(
            r#"UPDATE access.agents SET status = $4, status_at = clock_timestamp()
               WHERE tenant_id = $1 AND realm_id = $2 AND party = $3
                 AND status <> 'retired' AND status <> $4"#,
            tenant,
            realm,
            party.as_slice(),
            status,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Opens a sponsorship of `agent` by `subject` (AG-41).
    ///
    /// # Errors
    /// [`StoreError`]; an open one already is an integrity error.
    pub async fn open_sponsorship(
        &mut self,
        agent: [u8; 16],
        subject: [u8; 16],
        exercise: &[u8; 32],
    ) -> Result<(), StoreError> {
        let (tenant, realm) = self.org_scope()?;
        sqlx::query!(
            r#"INSERT INTO access.agent_sponsors
                 (tenant_id, realm_id, agent, subject_id, assigned_exercise)
               VALUES ($1, $2, $3, $4, $5)"#,
            tenant,
            realm,
            agent.as_slice(),
            Uuid::from_bytes(subject),
            exercise.as_slice(),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Ends the open sponsorship of `agent` by `subject`; `false` when none was open.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn end_sponsorship(
        &mut self,
        agent: [u8; 16],
        subject: [u8; 16],
        by: &str,
        exercise: Option<&[u8; 32]>,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let done = sqlx::query!(
            r#"UPDATE access.agent_sponsors
               SET ended_at = clock_timestamp(), ended_by = $5, ended_exercise = $6
               WHERE tenant_id = $1 AND realm_id = $2 AND agent = $3 AND subject_id = $4
                 AND ended_at IS NULL"#,
            tenant,
            realm,
            agent.as_slice(),
            Uuid::from_bytes(subject),
            by,
            exercise.map(<[u8; 32]>::as_slice),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Every sponsorship episode of `agent`, oldest first.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn sponsorships(&mut self, agent: [u8; 16]) -> Result<Vec<SponsorRow>, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let rows = sqlx::query!(
            r#"SELECT subject_id, assigned_exercise,
                      (extract(epoch FROM assigned_at) * 1000)::bigint AS "assigned_ms!",
                      (extract(epoch FROM ended_at) * 1000)::bigint AS ended_ms, ended_by,
                      ended_exercise
               FROM access.agent_sponsors
               WHERE tenant_id = $1 AND realm_id = $2 AND agent = $3
               ORDER BY assigned_at, sponsorship_id"#,
            tenant,
            realm,
            agent.as_slice(),
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(SponsorRow {
                    subject: *r.subject_id.as_bytes(),
                    assigned: id32(r.assigned_exercise)?,
                    assigned_ms: ms(r.assigned_ms),
                    ended_ms: r.ended_ms.map(ms),
                    ended_by: r.ended_by,
                    ended: r.ended_exercise.map(id32).transpose()?,
                })
            })
            .collect()
    }

    /// The agents `subject` sponsors now.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn sponsored_by(&mut self, subject: [u8; 16]) -> Result<Vec<[u8; 16]>, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let rows = sqlx::query_scalar!(
            r#"SELECT agent FROM access.agent_sponsors
               WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND ended_at IS NULL
               ORDER BY agent"#,
            tenant,
            realm,
            Uuid::from_bytes(subject),
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter().map(id16).collect()
    }

    /// Records version `version` of template `name`.
    ///
    /// # Errors
    /// [`StoreError`]; an existing version is an integrity error.
    pub async fn insert_agent_template(&mut self, t: &TemplateRow) -> Result<(), StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let version = i64::try_from(t.version).map_err(|_| StoreError::Range)?;
        sqlx::query!(
            r#"INSERT INTO access.agent_templates
                 (tenant_id, realm_id, name, version, content, defined_exercise)
               VALUES ($1, $2, $3, $4, $5, $6)"#,
            tenant,
            realm,
            t.name,
            version,
            t.content.as_slice(),
            t.defined.as_slice(),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// The latest version of template `name`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn agent_template(&mut self, name: &str) -> Result<Option<TemplateRow>, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let row = sqlx::query!(
            r#"SELECT name, version, content, defined_exercise FROM access.agent_templates
               WHERE tenant_id = $1 AND realm_id = $2 AND name = $3
               ORDER BY version DESC LIMIT 1"#,
            tenant,
            realm,
            name,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        row.map(|r| {
            Ok(TemplateRow {
                name: r.name,
                version: u64::try_from(r.version).map_err(|_| StoreError::Corrupt)?,
                content: r.content,
                defined: id32(r.defined_exercise)?,
            })
        })
        .transpose()
    }
}
