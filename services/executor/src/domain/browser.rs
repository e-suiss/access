//! The agent's browser inside the person's microVM (E50, E54 (4), E61 (3), AG-40 (7), OP-156
//! m.3 (w)). Each task runs in its own context: its own profile, cookie jar and origin sets, and
//! nothing crosses from one task to another. A profile opens for a task only under the
//! Exercise that task runs. A password comes from the person's own password manager at the
//! moment it is typed, only into a page of the origin it was saved for, and never enters the
//! model's context or the trace: the model and the trace see only that a field was filled.

use std::collections::{BTreeMap, BTreeSet};

use access_kernel::combinator::Origins;
use suiss_crypto::secret::Secret;

/// Why the browser refuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BrowserError {
    /// No open context for this task.
    #[error("executor-task")]
    Task,
    /// The origin is outside the task's sets (E54 (4)).
    #[error("executor-origin")]
    Origin,
    /// The credential was saved for another origin (E50 (2)).
    #[error("executor-credential-origin")]
    CredentialOrigin,
    /// The task already has a context.
    #[error("executor-task-open")]
    Open,
}

/// The Exercise a task runs under: the only thing that opens a profile for it (E50 (3)).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Release {
    /// The allowed Exercise.
    pub exercise: [u8; 32],
    /// The task, a step of it.
    pub task: [u8; 32],
}

/// One cookie.
#[derive(Clone)]
pub struct Cookie {
    /// Its name.
    pub name: String,
    /// Its value; never shown to the model.
    pub value: Secret<String>,
}

impl std::fmt::Debug for Cookie {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cookie")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// A saved credential the person's password manager gives for one origin.
pub struct Credential {
    /// The origin it was saved for, `scheme://host[:port]`.
    pub origin: String,
    /// The user name.
    pub username: String,
    /// The password.
    pub password: Secret<String>,
}

/// What the page receives when a field is filled: the value goes to the page alone.
pub struct Fill {
    /// The field.
    pub field: String,
    /// The value typed into it.
    pub value: Secret<String>,
}

/// One task's context.
#[derive(Debug, Default)]
struct Context {
    exercise: [u8; 32],
    origins: Origins,
    cookies: BTreeMap<String, Vec<Cookie>>,
}

/// Every task context of one microVM.
#[derive(Debug, Default)]
pub struct Contexts {
    tasks: BTreeMap<[u8; 32], Context>,
}

fn origin_of(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let host = rest.split(['/', '?', '#']).next()?;
    (matches!(scheme, "https" | "http") && !host.is_empty() && !host.contains('@')).then(|| {
        format!(
            "{}://{}",
            scheme.to_ascii_lowercase(),
            host.to_ascii_lowercase()
        )
    })
}

impl Contexts {
    /// Opens a fresh context for `release`'s task with its Mandate's origin sets: an empty
    /// profile and an empty cookie jar of its own.
    ///
    /// # Errors
    /// [`BrowserError::Open`] when the task already has one.
    pub fn open(&mut self, release: Release, origins: Origins) -> Result<(), BrowserError> {
        if self.tasks.contains_key(&release.task) {
            return Err(BrowserError::Open);
        }
        self.tasks.insert(
            release.task,
            Context {
                exercise: release.exercise,
                origins,
                cookies: BTreeMap::new(),
            },
        );
        Ok(())
    }

    fn task(&self, task: &[u8; 32]) -> Result<&Context, BrowserError> {
        self.tasks.get(task).ok_or(BrowserError::Task)
    }

    /// Keeps `cookie` from a page of `url` in `task`'s jar; the task must be allowed to read it.
    ///
    /// # Errors
    /// [`BrowserError`].
    pub fn set_cookie(
        &mut self,
        task: &[u8; 32],
        url: &str,
        cookie: Cookie,
    ) -> Result<(), BrowserError> {
        let origin = origin_of(url).ok_or(BrowserError::Origin)?;
        let c = self.tasks.get_mut(task).ok_or(BrowserError::Task)?;
        if !c.origins.allows(&origin, false) {
            return Err(BrowserError::Origin);
        }
        c.cookies.entry(origin).or_default().push(cookie);
        Ok(())
    }

    /// The cookies `task` sends to `url`: its own, of that origin, never another task's.
    ///
    /// # Errors
    /// [`BrowserError`].
    pub fn cookies(&self, task: &[u8; 32], url: &str) -> Result<&[Cookie], BrowserError> {
        let origin = origin_of(url).ok_or(BrowserError::Origin)?;
        let c = self.task(task)?;
        if !c.origins.allows(&origin, false) {
            return Err(BrowserError::Origin);
        }
        Ok(c.cookies.get(&origin).map_or(&[], Vec::as_slice))
    }

    /// The Exercise `task` runs under.
    ///
    /// # Errors
    /// [`BrowserError::Task`].
    pub fn exercise(&self, task: &[u8; 32]) -> Result<[u8; 32], BrowserError> {
        Ok(self.task(task)?.exercise)
    }

    /// Fills the password field of a page of `url` in `task` from `credential` (E50 (2)): only
    /// a page the task may write to, and only of the origin the credential was saved for. The
    /// model and the trace get `note` alone.
    ///
    /// # Errors
    /// [`BrowserError`].
    pub fn fill_password(
        &self,
        task: &[u8; 32],
        url: &str,
        field: &str,
        credential: Credential,
        model: &mut ModelContext,
    ) -> Result<Fill, BrowserError> {
        let origin = origin_of(url).ok_or(BrowserError::Origin)?;
        let c = self.task(task)?;
        if !c.origins.allows(&origin, true) {
            return Err(BrowserError::Origin);
        }
        if origin_of(&credential.origin).as_deref() != Some(origin.as_str()) {
            return Err(BrowserError::CredentialOrigin);
        }
        model.push(&format!(
            "[a saved password was filled into {field} on {origin}]"
        ));
        Ok(Fill {
            field: String::from(field),
            value: credential.password,
        })
    }

    /// Ends `task`: its profile, cookies and storage go with it.
    pub fn close(&mut self, task: &[u8; 32]) {
        self.tasks.remove(task);
    }

    /// The tasks with an open context.
    #[must_use]
    pub fn open_tasks(&self) -> BTreeSet<[u8; 32]> {
        self.tasks.keys().copied().collect()
    }
}

/// What the agent's model sees of the browser: page text and notes, never a password, cookie
/// or card (AG-40 (7)). While a person has taken over, it sees nothing (E50 (4)).
#[derive(Debug, Default)]
pub struct ModelContext {
    lines: Vec<String>,
    taken_over: bool,
}

impl ModelContext {
    /// Adds a line the model may read.
    pub fn push(&mut self, line: &str) {
        if !self.taken_over {
            self.lines.push(String::from(line));
        }
    }

    /// A person takes the session over: the model's context and the trace are off until it
    /// is handed back.
    pub fn take_over(&mut self) {
        self.taken_over = true;
    }

    /// The person hands the session back.
    pub fn hand_back(&mut self) {
        self.taken_over = false;
    }

    /// The lines the model reads.
    #[must_use]
    pub fn lines(&self) -> &[String] {
        &self.lines
    }
}
