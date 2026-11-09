//! The executor's own store on real PostgreSQL (E62 (1), TI-6, OP-73): one job per Exercise, an
//! append at a taken position fails so a stale runner cannot act, and the history never
//! changes.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test code")]

// E62 (1), TI-6
#[tokio::test]
async fn one_job_per_exercise_and_a_stale_append_is_fenced_out() {
    let (store, _) = access_executor::testing::store().await.unwrap();
    let (job, fresh) = store
        .create([1; 16], ([2; 32], [3; 32]), "cloud", "{\"type\":\"x\"}")
        .await
        .unwrap();
    assert!(fresh);
    let (again, fresh) = store
        .create([9; 16], ([2; 32], [3; 32]), "local", "{\"type\":\"y\"}")
        .await
        .unwrap();
    assert_eq!((again, fresh), (job, false));
    assert!(store.append_at(job, 1, "{\"n\":1}").await.unwrap());
    assert!(!store.append_at(job, 1, "{\"n\":2}").await.unwrap());
    assert_eq!(store.append(job, "{\"n\":3}").await.unwrap(), 2);
    assert_eq!(
        store.history(job).await.unwrap(),
        vec!["{\"type\":\"x\"}", "{\"n\":1}", "{\"n\":3}"]
    );
    assert_eq!(store.history([7; 16]).await.unwrap(), Vec::<String>::new());
    assert_eq!(store.jobs(10).await.unwrap(), vec![job]);
}

// OP-73, E62 (1)
#[tokio::test]
async fn the_history_is_append_only() {
    let (store, pool) = access_executor::testing::store().await.unwrap();
    let (job, _) = store
        .create([1; 16], ([2; 32], [3; 32]), "customer", "{}")
        .await
        .unwrap();
    let refused = sqlx::query("UPDATE executor.events SET event = '[]' WHERE job = $1")
        .bind(&job[..])
        .execute(&pool)
        .await
        .unwrap_err();
    assert!(refused.to_string().contains("append-only"), "{refused}");
    let refused = sqlx::query("UPDATE executor.jobs SET kind = 'local' WHERE job = $1")
        .bind(&job[..])
        .execute(&pool)
        .await
        .unwrap_err();
    assert!(refused.to_string().contains("append-only"), "{refused}");
    assert_eq!(store.history(job).await.unwrap(), vec!["{}"]);
}
