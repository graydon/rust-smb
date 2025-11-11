//! Directory enumeration state tracking

use crate::protocol::messages::common::FileId;
use std::collections::HashMap;

/// Tracks the state of directory enumerations for each open directory handle
#[derive(Debug, Clone)]
pub struct EnumerationState {
    /// Current position in the enumeration (index of next entry to return)
    pub position: usize,
    /// Whether enumeration has been completed
    pub completed: bool,
    /// The search pattern used for this enumeration
    pub search_pattern: String,
}

impl EnumerationState {
    /// Create a new enumeration state
    pub fn new(search_pattern: String) -> Self {
        Self {
            position: 0,
            completed: false,
            search_pattern,
        }
    }

    /// Reset the enumeration to the beginning
    pub fn reset(&mut self) {
        self.position = 0;
        self.completed = false;
    }

    /// Advance the position by the specified count
    pub fn advance(&mut self, count: usize) {
        self.position += count;
    }

    /// Mark the enumeration as completed
    pub fn complete(&mut self) {
        self.completed = true;
    }
}

/// Manages enumeration states for all open directory handles
#[derive(Debug, Default)]
pub struct EnumerationManager {
    /// Map from file ID to enumeration state
    states: HashMap<FileId, EnumerationState>,
}

impl EnumerationManager {
    /// Create a new enumeration manager
    pub fn new() -> Self {
        Self {
            states: HashMap::new(),
        }
    }

    /// Get or create enumeration state for a file handle
    pub fn get_or_create(
        &mut self,
        file_id: &FileId,
        search_pattern: String,
    ) -> &mut EnumerationState {
        self.states
            .entry(*file_id)
            .or_insert_with(|| EnumerationState::new(search_pattern))
    }

    /// Get enumeration state for a file handle
    pub fn get(&self, file_id: &FileId) -> Option<&EnumerationState> {
        self.states.get(file_id)
    }

    /// Get mutable enumeration state for a file handle
    pub fn get_mut(&mut self, file_id: &FileId) -> Option<&mut EnumerationState> {
        self.states.get_mut(file_id)
    }

    /// Remove enumeration state for a closed file handle
    pub fn remove(&mut self, file_id: &FileId) {
        self.states.remove(file_id);
    }

    /// Reset enumeration state for a file handle
    pub fn reset(&mut self, file_id: &FileId) {
        if let Some(state) = self.states.get_mut(file_id) {
            state.reset();
        }
    }
}
