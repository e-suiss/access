//! Refresh single-flight (P50, §9.9.3 k.6, T41 item 4): refresh tokens rotate on every use and
//! a reused one ends the whole family, so two concurrent refreshes with the same token would
//! sign the client out. [`Refresher`] runs one refresh at a time: the first caller starts it,
//! every caller that arrives while it runs waits for the same result, and the next caller after
//! it ends starts a new one. Nothing is cached past the flight.
//!
//! If the caller running the refresh is dropped before it finishes, the waiting callers get
//! [`RefreshError::Abandoned`], never a token (fail closed); the next call starts again.

use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, Waker};
use std::vec::Vec;

use core::future::Future;
use core::pin::Pin;

/// Why a refresh produced no token.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RefreshError<E> {
    /// The refresh ran and failed.
    #[error("refresh-failed")]
    Failed(E),
    /// The caller running the refresh was dropped before it finished.
    #[error("refresh-abandoned")]
    Abandoned,
}

struct Flight<T, E> {
    result: Mutex<Option<Result<T, RefreshError<E>>>>,
    wakers: Mutex<Vec<Waker>>,
}

impl<T: Clone, E: Clone> Flight<T, E> {
    fn new() -> Self {
        Self {
            result: Mutex::new(None),
            wakers: Mutex::new(Vec::new()),
        }
    }

    fn finish(&self, result: Result<T, RefreshError<E>>) {
        let mut slot = self.result.lock().unwrap_or_else(PoisonError::into_inner);
        if slot.is_none() {
            *slot = Some(result);
        }
        drop(slot);
        let wakers =
            core::mem::take(&mut *self.wakers.lock().unwrap_or_else(PoisonError::into_inner));
        for w in wakers {
            w.wake();
        }
    }

    fn poll_result(&self, cx: &Context<'_>) -> Poll<Result<T, RefreshError<E>>> {
        let mut wakers = self.wakers.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(r) = self
            .result
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
        {
            return Poll::Ready(r.clone());
        }
        if !wakers.iter().any(|w| w.will_wake(cx.waker())) {
            wakers.push(cx.waker().clone());
        }
        Poll::Pending
    }
}

struct Wait<T, E>(Arc<Flight<T, E>>);

impl<T: Clone, E: Clone> Future for Wait<T, E> {
    type Output = Result<T, RefreshError<E>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.poll_result(cx)
    }
}

struct State<T, E> {
    flight: Option<Arc<Flight<T, E>>>,
    waiting: usize,
}

/// One refresh at a time for everyone who shares this value.
pub struct Refresher<T, E> {
    state: Mutex<State<T, E>>,
}

impl<T, E> core::fmt::Debug for Refresher<T, E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Refresher").finish_non_exhaustive()
    }
}

impl<T: Clone, E: Clone> Default for Refresher<T, E> {
    fn default() -> Self {
        Self::new()
    }
}

/// Ends the flight when the leader's future is dropped, finished or not.
struct Leader<'a, T: Clone, E: Clone> {
    owner: &'a Refresher<T, E>,
    flight: Arc<Flight<T, E>>,
}

impl<T: Clone, E: Clone> Drop for Leader<'_, T, E> {
    fn drop(&mut self) {
        self.flight.finish(Err(RefreshError::Abandoned));
        let mut state = self.owner.lock();
        if state
            .flight
            .as_ref()
            .is_some_and(|f| Arc::ptr_eq(f, &self.flight))
        {
            state.flight = None;
        }
    }
}

enum Role<T, E> {
    Lead(Arc<Flight<T, E>>),
    Follow(Arc<Flight<T, E>>),
}

impl<T: Clone, E: Clone> Refresher<T, E> {
    /// No refresh in flight.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State {
                flight: None,
                waiting: 0,
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State<T, E>> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// How many callers are waiting on a refresh another caller runs.
    #[must_use]
    pub fn waiting(&self) -> usize {
        self.lock().waiting
    }

    /// Runs `start` unless a refresh is already in flight, in which case it waits for that one;
    /// every caller of one flight gets the same result.
    ///
    /// # Errors
    /// [`RefreshError`].
    pub async fn refresh<F, Fut>(&self, start: F) -> Result<T, RefreshError<E>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, E>>,
    {
        let role = {
            let mut state = self.lock();
            if let Some(f) = &state.flight {
                let f = Arc::clone(f);
                state.waiting = state.waiting.saturating_add(1);
                Role::Follow(f)
            } else {
                let f = Arc::new(Flight::new());
                state.flight = Some(Arc::clone(&f));
                Role::Lead(f)
            }
        };
        match role {
            Role::Follow(flight) => {
                let out = Wait(flight).await;
                let mut state = self.lock();
                state.waiting = state.waiting.saturating_sub(1);
                out
            }
            Role::Lead(flight) => {
                let leader = Leader {
                    owner: self,
                    flight: Arc::clone(&flight),
                };
                let out = start().await.map_err(RefreshError::Failed);
                flight.finish(out.clone());
                drop(leader);
                out
            }
        }
    }
}
