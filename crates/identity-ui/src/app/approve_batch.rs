//! CT1 batch approval (OP-157 m.3 (m), §13.7.3, §8.17.6.3, SEC26): at most ten requests of one
//! requester and one action class, in a realm that opened `idp.realm.approval_batch`. Every
//! item is shown, has its own statement and its own assertion, and becomes its own
//! contribution. A single item outside these rules refuses the whole batch; nothing here
//! approves "all".

use access_identity_oauth::ports::RealmEntry;
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::tier::Tier;
use access_store::approvals::{self as store, ApprovalChannel};
use access_store::identity::TenantTx;
use serde_json::{Value, json};

use super::approve::{Prepared, call};
use super::me::{Devices, unavailable};
use super::{Body, Browser, Hosted, Reply};
use crate::domain::approval::{
    ApprovalFinish, BATCH_MAX, BatchFinish, BatchStart, Kept, action_class, envelope,
    requester_party,
};
use crate::domain::frontend::{ApproveQuery, rfc3339};
use crate::domain::message::TextId;
use crate::ports::{ApprovalClaims, Approvals, Kits, Messages, RealmKit};

const FLOW_LEN: usize = 16;

fn invalid(why: &'static str) -> Reply {
    Reply::json(
        400,
        json!({
            "type": "urn:suiss:access:problem:approval-batch-invalid",
            "status": 400,
            "code": "approval-batch-invalid",
            "title": why,
        }),
    )
}

/// The flow id names the batch's item ids in order; each item stays bound to the session that
/// opened it.
fn flow_of(items: &[[u8; 16]]) -> String {
    let mut bytes = Vec::with_capacity(items.len().saturating_mul(FLOW_LEN));
    for i in items {
        bytes.extend_from_slice(i);
    }
    b64url_encode(&bytes)
}

fn items_of(flow: &str) -> Option<Vec<[u8; 16]>> {
    let bytes = b64url_decode(flow).ok()?;
    if bytes.is_empty() || bytes.len().rem_euclid(FLOW_LEN) != 0 {
        return None;
    }
    Some(bytes.as_chunks::<FLOW_LEN>().0.to_vec())
}

fn problem_of(reply: &Reply) -> Value {
    match &reply.body {
        Body::Problem(p) => json!({ "status": p.status, "code": p.code, "title": p.title }),
        Body::Json(v) => v.clone(),
        _ => Value::Null,
    }
}

impl<K, C, M> Hosted<K, C, M>
where
    K: Kits,
    C: crate::ports::Clock + Sync,
    M: Messages,
{
    async fn batch_open(&self, kit: &RealmKit) -> Result<bool, Reply> {
        let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm)
            .await
            .map_err(|_| unavailable())?;
        let open = store::approval_channel_enabled(&mut t, ApprovalChannel::Batch)
            .await
            .map_err(|_| unavailable())?;
        t.commit().await.map_err(|_| unavailable())?;
        Ok(open)
    }

    /// `POST /v1/approve/batch`: opens every item or none; each gets its own statement and its
    /// own assertion options, and is listed in full.
    #[expect(
        clippy::too_many_lines,
        reason = "one batch: bounds, same requester and class, CT1, every item faithful, opened"
    )]
    pub async fn start_batch<A, I, P: Approvals, Q>(
        &self,
        devices: &Devices<A, I, P, Q>,
        entry: &RealmEntry,
        b: &Browser<'_>,
        body: &BatchStart,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let now = self.clock.now_ms();
        if body.requests.is_empty() || body.requests.len() > BATCH_MAX {
            return invalid("A batch holds one to ten requests");
        }
        match self.batch_open(&kit).await {
            Ok(true) => {}
            Ok(false) => return invalid("Batch approval is not open in this realm"),
            Err(r) => return r,
        }
        let session = match self.approver_session(&kit, b).await {
            Ok(s) => s,
            Err(r) => return r,
        };
        let mut opened = Vec::with_capacity(body.requests.len());
        let mut class: Option<(Option<[u8; 16]>, String)> = None;
        for request in &body.requests {
            let query = ApproveQuery {
                request: request.clone(),
                redirect_uri: body.redirect_uri.clone(),
                state: body.state.clone(),
            };
            let row = match call(&self.db, &self.products, &kit, &query, now).await {
                Ok(r) => r,
                Err(r) => return r,
            };
            if opened
                .iter()
                .any(|(r, _): &(access_store::approvals::ApprovalRow, Prepared)| r.id == row.id)
            {
                return invalid("A batch lists each request once");
            }
            let Ok(value) = serde_json::from_slice::<Value>(&row.request) else {
                return unavailable();
            };
            let (Ok(kept),) = (serde_json::from_slice::<Kept>(&row.contribution),) else {
                return unavailable();
            };
            let Ok(env) = envelope(&kept.contribution) else {
                return unavailable();
            };
            let Some(action) = action_class(&value, &env.class) else {
                return invalid("A batch needs requests of one action class");
            };
            let this = (requester_party(&value), action);
            if this.0.is_none() || class.as_ref().is_some_and(|c| *c != this) {
                return invalid("A batch needs one requester and one action class");
            }
            class = Some(this);
            let prepared = match self
                .opening_of(devices, &kit, &session.subject, &row, now)
                .await
            {
                Ok(p) => p,
                Err(r) if r.status >= 500 => return r,
                Err(_) => return invalid("A batch item can't be approved here"),
            };
            if prepared.tier > Tier::Ct1 {
                return invalid("Batch approval is only for the lowest-consequence requests");
            }
            opened.push((row, prepared));
        }
        // §8.17.6.3
        let mut items = Vec::with_capacity(opened.len());
        let mut ids = Vec::with_capacity(opened.len());
        for (row, p) in &opened {
            let started = async {
                let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm).await?;
                let ok = store::start_approval(
                    &mut t,
                    &row.id,
                    &session.id,
                    &p.statement.0,
                    &p.aas_bytes,
                    now,
                )
                .await?;
                t.commit().await?;
                Ok::<_, access_store::StoreError>(ok)
            };
            match started.await {
                Ok(true) => {}
                Ok(false) => return invalid("A batch item was opened already"),
                Err(_) => return unavailable(),
            }
            ids.push(row.id);
            let mut view = serde_json::to_value(&p.view).unwrap_or(Value::Null);
            if let Some(v) = view.as_object_mut() {
                v.insert(String::from("expires_at"), json!(rfc3339(p.act.expires_at)));
            }
            items.push(json!({
                "flow": b64url_encode(&row.id),
                "render": view,
                "options": p.options,
            }));
        }
        Reply::json(
            201,
            json!({
                "flow": flow_of(&ids),
                "title": crate::domain::approval::say(
                    TextId::ApprovalBatchTitle,
                    &[("count", &opened.len().to_string())],
                ),
                "items": items,
            }),
        )
    }

    /// `POST /v1/approve/batch/{flow}`: runs each item's assertion and contribution; each answer
    /// stands on its own, and the reply says how each went.
    pub async fn finish_batch<A, I, P: Approvals, Q: ApprovalClaims>(
        &self,
        devices: &Devices<A, I, P, Q>,
        entry: &RealmEntry,
        b: &Browser<'_>,
        flow: &str,
        body: &BatchFinish,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let now = self.clock.now_ms();
        let session = match self.approver_session(&kit, b).await {
            Ok(s) => s,
            Err(r) => return r,
        };
        let Some(ids) = items_of(flow) else {
            return invalid("This batch is not waiting here");
        };
        if body.items.len() != ids.len()
            || body
                .items
                .iter()
                .zip(&ids)
                .any(|(item, id)| b64url_decode(&item.flow).ok().as_deref() != Some(id.as_slice()))
        {
            return invalid("The answers don't match this batch");
        }
        let mut results = Vec::with_capacity(ids.len());
        for item in &body.items {
            let finish = ApprovalFinish {
                credential: item.credential.clone(),
                redirect_uri: body.redirect_uri.clone(),
                state: body.state.clone(),
                app_factor: None,
            };
            results.push(
                match self
                    .finish_flow(
                        devices,
                        &kit,
                        &session.subject,
                        &session.id,
                        &item.flow,
                        &finish,
                        now,
                    )
                    .await
                {
                    Ok(f) => json!({
                        "flow": item.flow,
                        "exercise": b64url_encode(&f.exercise),
                        "render_digest": b64url_encode(&f.render_digest),
                        "claim": b64url_encode(&f.claim),
                    }),
                    Err(reply) => json!({ "flow": item.flow, "problem": problem_of(&reply) }),
                },
            );
        }
        let actor = kit.ids.encode("usr", session.subject).unwrap_or_default();
        let audited = async {
            let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm).await?;
            t.audit(&access_store::audit::AuditEvent {
                event_type: "approval.batch",
                actor: &actor,
                target: &actor,
                correlation: "approval",
            })
            .await?;
            t.commit().await
        };
        if let Err(error) = audited.await {
            tracing::warn!(%error, "approval batch audit not written");
        }
        Reply::json(200, json!({ "items": results }))
    }
}
