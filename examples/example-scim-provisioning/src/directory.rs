//! The local directory.

use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::user::User;

/// The local directory the SCIM Events are mirrored into, in memory. An application would keep
/// its own user table here.
#[derive(Debug, Default)]
pub struct UserDirectory {
    users: Mutex<BTreeMap<String, User>>,
}

impl UserDirectory {
    /// Stores the user, replacing the user with the same id.
    pub fn save(&self, user: User) {
        self.users.lock().unwrap().insert(user.id.clone(), user);
    }

    /// The user with the id, if the directory has one.
    pub fn find(&self, id: &str) -> Option<User> {
        self.users.lock().unwrap().get(id).cloned()
    }

    /// Changes the user, if it is in the directory.
    ///
    /// Returns the changed user, `None` if the directory has no such user.
    pub fn update(&self, id: &str, change: impl FnOnce(User) -> User) -> Option<User> {
        let mut users = self.users.lock().unwrap();
        let user = users.remove(id)?;
        let changed = change(user);
        users.insert(id.to_owned(), changed.clone());
        Some(changed)
    }

    /// Removes the user, returning it if the directory had one.
    pub fn remove(&self, id: &str) -> Option<User> {
        self.users.lock().unwrap().remove(id)
    }

    /// All users, by id.
    pub fn all(&self) -> Vec<User> {
        self.users.lock().unwrap().values().cloned().collect()
    }
}
