use crate::models::GooglePlayApp;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub enum FetchStatus {
    Pending,
    Fetching,
    Success(GooglePlayApp),
    Error(String),
}

pub struct GooglePlayQueue {
    pub queue: Arc<Mutex<VecDeque<String>>>,
    pub results: Arc<Mutex<HashMap<String, FetchStatus>>>,
    pub is_running: Arc<Mutex<bool>>,
}
